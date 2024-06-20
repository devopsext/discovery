package discovery

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type LabelsOptions struct {
	Query       string
	QueryPeriod string
	QueryStep   string
	Schedule    string
	Name        string
}

type Labels struct {
	source         string
	prometheus     *toolsVendors.Prometheus
	prometheusOpts toolsVendors.PrometheusOptions
	options        LabelsOptions
	logger         sreCommon.Logger
	observability  *common.Observability
	processors     *common.Processors
	nameTemplate   *toolsRender.TextTemplate
}

type LabelsSinkObject struct {
	sinkMap common.SinkMap
	labels  *Labels
}

func (ls *LabelsSinkObject) Map() common.SinkMap {
	return ls.sinkMap
}

func (ls *LabelsSinkObject) Options() interface{} {
	return ls.labels.options
}

func (l *Labels) Name() string {
	return "Labels"
}

func (l *Labels) Source() string {
	return l.source
}

func (l *Labels) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		l.logger.Error(err)
		return def
	}
	return s1
}

func (l *Labels) findLabels(vectors []*common.PrometheusResponseDataVector) common.LabelsMap {

	ret := make(common.LabelsMap)
	gid := utils.GoRoutineID()

	l1 := len(vectors)
	l.logger.Debug("[%d] %s: Labels found %d series", gid, l.source, l1)
	if len(vectors) == 0 {
		return ret
	}

	for _, v := range vectors {

		if len(v.Labels) < 2 {
			l.logger.Debug("[%d] %s: Labels not found, min requirements (2): %v", gid, l.source, v.Labels)
			continue
		}

		name := l.render(l.nameTemplate, l.options.Name, v.Labels)
		if utils.IsEmpty(name) {
			l.logger.Debug("[%d] %s: Labels no name found in labels, but: %v", gid, l.source, v.Labels)
			continue
		}
		ret[name] = v.Labels
	}
	return ret
}

func (l *Labels) Discover() {

	l.logger.Debug("%s: HTTP discovery by query: %s", l.source, l.options.Query)
	if !utils.IsEmpty(l.options.QueryPeriod) {
		// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
		t := time.Now().UTC()
		l.prometheusOpts.From = common.ParsePeriodFromNow(l.options.QueryPeriod, t)
		l.prometheusOpts.To = strconv.Itoa(int(t.Unix()))
		l.prometheusOpts.Step = l.options.QueryStep
		if utils.IsEmpty(l.prometheusOpts.Step) {
			l.prometheusOpts.Step = "15s"
		}
		l.logger.Debug("%s: Labels discovery range: %s <-> %s", l.source, l.prometheusOpts.From, l.prometheusOpts.To)
	}

	data, err := l.prometheus.CustomGet(l.prometheusOpts)
	if err != nil {
		l.logger.Error(err)
		return
	}

	var res common.PrometheusResponse
	if err := json.Unmarshal(data, &res); err != nil {
		l.logger.Error(err)
		return
	}

	if res.Status != "success" {
		l.logger.Error(res.Status)
		return
	}

	if (res.Data == nil) || (len(res.Data.Result) == 0) {
		l.logger.Error("%s: Labels empty data on response", l.source)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		l.logger.Error("%s: Labels only vector and matrix are allowed", l.source)
		return
	}

	labels := l.findLabels(res.Data.Result)
	if len(labels) == 0 {
		l.logger.Debug("%s: Labels not found any labels according query", l.source)
		return
	}
	l.logger.Debug("%s: Labels found %d labels according query. Processing...", l.source, len(labels))

	l.processors.Process(l, &LabelsSinkObject{
		sinkMap: common.ConvertLabelsMapToSinkMap(labels),
		labels:  l,
	})
}

func NewLabels(source string, prometheusOptions common.PrometheusOptions, options LabelsOptions, observability *common.Observability, processors *common.Processors) *Labels {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: Labels has no prometheus URL. Skipped", source)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: Labels has no query. Skipped", source)
		return nil
	}

	if utils.IsEmpty(options.Name) {
		logger.Debug("%s: Labels has no name. Skipped", source)
		return nil
	}

	nameOpts := toolsRender.TemplateOptions{
		Content: options.Name,
		Name:    "labels-name",
	}
	nameTemplate, err := toolsRender.NewTextTemplate(nameOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	prometheusOpts := toolsVendors.PrometheusOptions{
		URL:      prometheusOptions.URL,
		User:     prometheusOptions.User,
		Password: prometheusOptions.Password,
		Timeout:  prometheusOptions.Timeout,
		Insecure: prometheusOptions.Insecure,
		Query:    options.Query,
	}

	return &Labels{
		source:         source,
		prometheus:     toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts: prometheusOpts,
		options:        options,
		logger:         logger,
		observability:  observability,
		processors:     processors,
		nameTemplate:   nameTemplate,
	}
}
