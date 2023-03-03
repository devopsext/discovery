package common

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
)

type TelegrafInputPrometheusHttpMetric struct {
	Name     string            `toml:"name"`
	Query    string            `toml:"query"`
	UniqueBy []string          `toml:"unique_by,omitempty"`
	Tags     map[string]string `toml:"tags,omitempty"`
}

type TelegrafInputPrometheusHttpAvailability struct {
	Name     string            `toml:"name"`
	Query    string            `toml:"query"`
	UniqueBy []string          `toml:"unique_by,omitempty"`
	Tags     map[string]string `toml:"tags,omitempty"`
}

type TelegrafInputPrometheusHttp struct {
	URL           string                               `toml:"url"`
	Version       string                               `toml:"version"`
	Params        string                               `toml:"params"`
	Interval      string                               `toml:"interval"`
	Timeout       string                               `toml:"timeout"`
	Duration      string                               `toml:"duration"`
	Prefix        string                               `toml:"prefix"`
	Metric        []*TelegrafInputPrometheusHttpMetric `toml:"metric"`
	Tags          map[string]string                    `toml:"tags,omitempty"`
	Include       []string                             `toml:"taginclude,omitempty"`
	SkipEmptyTags bool                                 `toml:"skip_empty_tags"`
}

type TelegrafInputs struct {
	PrometheusHttp []*TelegrafInputPrometheusHttp `toml:"prometheus_http,omitempty"`
}

type TelegrafConfigOptions struct {
	URL              string
	Version          string
	Params           string
	Interval         string
	Timeout          string
	Duration         string
	Prefix           string
	QualityName      string
	QualityRange     string
	QualityEvery     string
	QualityPoints    int
	QualityQuery     string
	AvailbailityName string
	MetricName       string
	DefaultTags      []string
}

type TelegrafConfig struct {
	Inputs TelegrafInputs `toml:"inputs"`
}

//[[inputs.prometheus_http]]
//  [inputs.prometheus_http.tags]
//  [[inputs.prometheus_http.metric]]
//    [inputs.prometheus_http.metric.tags]

func (ti *TelegrafInputPrometheusHttp) updateIncludeTags(tags []string) {

	for _, tag := range tags {
		if !StringInArr(tag, ti.Include) {
			ti.Include = append(ti.Include, tag)
		}
	}
}

func (ti *TelegrafInputPrometheusHttp) sanitizeQuery(query string) string {

	res := strings.ReplaceAll(query, "\"", "'")
	res = strings.ReplaceAll(res, "\n", "")
	return res
}

func (ti *TelegrafInputPrometheusHttp) setVars(q string, vars map[string]string) string {
	for k, v := range vars {
		q = strings.ReplaceAll(q, fmt.Sprintf("$%s", k), v)
	}
	return q
}

func (ti *TelegrafInputPrometheusHttp) render(def string, obj interface{}) string {

	tpl, err := toolsRender.NewTextTemplate(toolsRender.TemplateOptions{Content: def}, nil)
	if err != nil {
		return def
	}

	s, err := RenderTemplate(tpl, def, obj)
	if err != nil {
		return def
	}
	return s
}

func (ti *TelegrafInputPrometheusHttp) buildQualities(qualities []*BaseQuality, opts TelegrafConfigOptions, vars map[string]string) {

	metric := &TelegrafInputPrometheusHttpMetric{}
	metric.Name = opts.QualityName
	var queries []string

	for _, v := range qualities {

		if utils.IsEmpty(strings.TrimSpace(v.Query)) {
			continue
		}

		bq := &BaseQuality{
			Range:  IfDef(v.Range, opts.QualityRange).(string),
			Every:  IfDef(v.Every, opts.QualityEvery).(string),
			Points: IfDef(v.Points, opts.QualityPoints).(int),
			Query:  ti.setVars(v.Query, vars),
		}

		qe := ti.render(opts.QualityQuery, bq)
		qe = ti.sanitizeQuery(qe)
		queries = append(queries, qe)
	}

	metric.Query = fmt.Sprintf("(%s)/%d", strings.Join(queries, " + "), len(queries))
	metric.Tags = make(map[string]string)

	/*for k, l := range config.Labels {
		lnew := decideLabel(metric.Name, l)
		if lnew == "" {
			continue
		}
		metric.Tags[k] = setVars(lnew, config.Vars)
	}*/

	ti.Metric = append(ti.Metric, metric)
}

func (ti *TelegrafInputPrometheusHttp) buildAvailability(availbility *BaseAvailability, opts TelegrafConfigOptions) {

}

func (ti *TelegrafInputPrometheusHttp) buildMetrics(metrics []*BaseMetric, opts TelegrafConfigOptions) {

}

func (tc *TelegrafConfig) GenerateServiceBytes(s *Service, opts TelegrafConfigOptions) ([]byte, error) {

	input := &TelegrafInputPrometheusHttp{}
	input.URL = opts.URL
	input.Version = opts.Version
	input.Params = opts.Params
	input.Interval = opts.Interval
	input.Timeout = opts.Timeout
	input.Duration = opts.Duration
	input.Prefix = opts.Prefix
	input.Tags = make(map[string]string)
	input.SkipEmptyTags = true

	for _, c := range s.Configs {

		input.buildQualities(c.Qualities, opts, c.Vars)
		input.buildAvailability(c.Availability, opts)
		input.buildMetrics(c.Metrics, opts)
	}

	/*
		// adding metric
		for _, v := range serviceConfig.Metrics {
			m, err := getMetricInput(serviceConfig, v)
			if err == nil {
				input.updateIncludeTags(getKeys(m.Tags))
				input.Metric = append(input.Metric, m)
			}
		}
	*/
	input.updateIncludeTags(opts.DefaultTags)
	tc.Inputs.PrometheusHttp = append(tc.Inputs.PrometheusHttp, input)

	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	if err := toml.NewEncoder(w).Encode(tc); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
