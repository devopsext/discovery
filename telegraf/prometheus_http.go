package telegraf

import (
	"fmt"
	"sort"
	"strings"

	"github.com/devopsext/discovery/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
)

type InputPrometheusHttpFile struct {
	Name string `toml:"name"`
	Path string `toml:"path"`
	Type string `toml:"type,omitempty"`
}

type InputPrometheusHttpMetric struct {
	Name     string            `toml:"name"`
	Round    *int              `toml:"round,omitempty"`
	Query    string            `toml:"query"`
	UniqueBy []string          `toml:"unique_by,omitempty"`
	Tags     map[string]string `toml:"tags,omitempty"`
}

type InputPrometheusHttpAvailability struct {
	Name     string            `toml:"name"`
	Round    *int              `toml:"round,omitempty"`
	Query    string            `toml:"query"`
	UniqueBy []string          `toml:"unique_by,omitempty"`
	Tags     map[string]string `toml:"tags,omitempty"`
}

type InputPrometheusHttp struct {
	Name          string                             `toml:"name"`
	URL           string                             `toml:"url"`
	User          string                             `toml:"user,omitempty"`
	Password      string                             `toml:"password,omitempty"`
	Version       string                             `toml:"version"`
	Params        string                             `toml:"params,omitempty"`
	Interval      string                             `toml:"interval"`
	Timeout       string                             `toml:"timeout"`
	Duration      string                             `toml:"duration,omitempty"`
	Prefix        string                             `toml:"prefix"`
	File          []*InputPrometheusHttpFile         `toml:"file"`
	Metric        []*InputPrometheusHttpMetric       `toml:"metric"`
	Availability  []*InputPrometheusHttpAvailability `toml:"metric"`
	Tags          map[string]string                  `toml:"tags,omitempty"`
	Include       []string                           `toml:"taginclude,omitempty"`
	SkipEmptyTags bool                               `toml:"skip_empty_tags"`
	observability *common.Observability
}

type InputPrometheusHttpOptions struct {
	Interval         string
	URL              string
	User             string
	Password         string
	Version          string
	Params           string
	Timeout          string
	Duration         string
	Prefix           string
	QualityName      string
	QualityRange     string
	QualityEvery     string
	QualityPoints    int
	QualityQuery     string
	AvailabilityName string
	MetricName       string
	DefaultTags      []string
	VarFormat        string
}

//[[inputs.prometheus_http]]
//  [inputs.prometheus_http.tags]
//  [[inputs.prometheus_http.file]]
//  [[inputs.prometheus_http.metric]]
//    [inputs.prometheus_http.metric.tags]

func (ti *InputPrometheusHttp) updateIncludeTags(tags []string) {

	for _, tag := range tags {
		if !common.StringInArr(tag, ti.Include) {
			ti.Include = append(ti.Include, tag)
		}
	}
}

func (ti *InputPrometheusHttp) sanitizeQuery(query string) string {

	res := strings.ReplaceAll(query, "\"", "'")
	res = strings.ReplaceAll(res, "\n", "")
	return res
}

func (ti *InputPrometheusHttp) setVars(q, f string, vars map[string]string) string {

	keys := common.GetStringKeys(vars)
	sort.Slice(keys, func(i, j int) bool {
		l1, l2 := len(keys[i]), len(keys[j])
		if l1 != l2 {
			return l1 > l2
		}
		return keys[i] > keys[j]
	})

	for _, k := range keys {
		q = strings.ReplaceAll(q, fmt.Sprintf(f, k), vars[k])
	}
	return q
}

func (ti *InputPrometheusHttp) render(def string, obj interface{}) string {

	tpl, err := toolsRender.NewTextTemplate(toolsRender.TemplateOptions{Content: def}, ti.observability)
	if err != nil {
		ti.observability.Logs().Error(err)
		return def
	}

	s, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		ti.observability.Logs().Error(err)
		return def
	}
	return s
}

func (ti *InputPrometheusHttp) renderLabels(name, tpl string, tags map[string]string,
	vars map[string]string, files map[string]interface{}) map[string]string {

	m := make(map[string]interface{})
	m["name"] = name
	m["tags"] = tags
	m["vars"] = vars
	m["files"] = files
	s := ti.render(tpl, m)
	kv := utils.MapGetKeyValues(s)

	return common.MergeStringMaps(tags, kv)
}

func (ti *InputPrometheusHttp) buildTags(labels map[string]string, f string, vars map[string]string) map[string]string {

	r := make(map[string]string)

	for k, l := range labels {
		r[k] = ti.setVars(l, f, vars)
	}
	return r
}

func (ti *InputPrometheusHttp) buildQualities(s *common.Object, qualities []*common.BaseQuality, tpl string,
	opts InputPrometheusHttpOptions,
	labels map[string]string, vars map[string]string, files map[string]interface{}) {

	if utils.IsEmpty(opts.QualityQuery) {
		return
	}

	metric := &InputPrometheusHttpMetric{}
	metric.Name = opts.QualityName
	var queries []string

	for _, v := range qualities {

		if utils.IsEmpty(strings.TrimSpace(v.Query)) {
			continue
		}

		bq := &common.BaseQuality{
			Range:  common.IfDef(v.Range, opts.QualityRange).(string),
			Every:  common.IfDef(v.Every, opts.QualityEvery).(string),
			Points: common.IfDef(v.Points, opts.QualityPoints).(int),
			Query:  ti.setVars(v.Query, opts.VarFormat, vars),
		}

		qe := ti.render(opts.QualityQuery, bq)
		qe = ti.sanitizeQuery(qe)
		queries = append(queries, qe)
	}

	qe := fmt.Sprintf("(%s)/%d", strings.Join(queries, " + "), len(queries))
	if !common.StringContainsAny(qe, s.Metrics) {
		return
	}

	metric.Query = qe
	tags := ti.buildTags(labels, opts.VarFormat, vars)
	tags = ti.renderLabels(metric.Name, tpl, tags, vars, files)

	keys := common.GetStringKeys(tags)
	sort.Strings(keys)
	ti.updateIncludeTags(keys)
	metric.Tags = tags
	ti.Metric = append(ti.Metric, metric)
}

func (ti *InputPrometheusHttp) buildAvailability(s *common.Object, baseAvailability *common.BaseAvailability, tpl string,
	opts InputPrometheusHttpOptions,
	labels map[string]string, vars map[string]string, files map[string]interface{}) {

	if baseAvailability == nil {
		return
	}

	if baseAvailability.Disabled {
		return
	}

	for _, a := range baseAvailability.Queries {

		qe := ti.setVars(a.Query, opts.VarFormat, vars)
		if !common.StringContainsAny(qe, s.Metrics) {
			continue
		}

		availability := &InputPrometheusHttpAvailability{}

		if a.Suffix != "" {
			availability.Name = fmt.Sprintf("%s:%s", opts.AvailabilityName, a.Suffix)
		} else {
			availability.Name = opts.AvailabilityName
		}

		availability.Round = a.Round
		availability.Query = ti.sanitizeQuery(qe)
		tags1 := ti.buildTags(labels, opts.VarFormat, vars)
		tags2 := ti.buildTags(a.Labels, opts.VarFormat, vars)
		tags := common.MergeStringMaps(tags1, tags2)
		tags = ti.renderLabels(availability.Name, tpl, tags, vars, files)
		keys := common.GetStringKeys(tags)
		sort.Strings(keys)
		ti.updateIncludeTags(keys)
		availability.Tags = tags
		ti.Availability = append(ti.Availability, availability)
	}

}

func (ti *InputPrometheusHttp) buildMetrics(s *common.Object, metrics []*common.BaseMetric, tpl string,
	opts InputPrometheusHttpOptions,
	labels map[string]string, vars map[string]string, files map[string]interface{}) {

	for _, m := range metrics {

		if m.Disabled {
			continue
		}

		qe := ti.setVars(m.Query, opts.VarFormat, vars)

		if !common.StringContainsAny(qe, s.Metrics) {
			continue
		}

		metric := &InputPrometheusHttpMetric{}
		metric.Name = common.IfDef(m.Name, opts.MetricName).(string)
		metric.Round = m.Round
		metric.Query = ti.sanitizeQuery(qe)
		metric.UniqueBy = m.UniqueBy

		tags1 := ti.buildTags(labels, opts.VarFormat, vars)
		tags2 := ti.buildTags(m.Labels, opts.VarFormat, vars)
		tags := common.MergeStringMaps(tags1, tags2)
		tags = ti.renderLabels(metric.Name, tpl, tags, vars, files)

		keys := common.GetStringKeys(tags)
		sort.Strings(keys)
		ti.updateIncludeTags(keys)
		metric.Tags = tags
		ti.Metric = append(ti.Metric, metric)
	}
}
