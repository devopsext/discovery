package discovery

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type TCPOptions struct {
	Query       string
	QueryPeriod string
	QueryStep   string
	Schedule    string
	Pattern     string
	Names       string
	Exclusion   string
	NoSSL       string
}

type TCP struct {
	source         string
	prometheus     *toolsVendors.Prometheus
	prometheusOpts toolsVendors.PrometheusOptions
	options        TCPOptions
	logger         sreCommon.Logger
	observability  *common.Observability
	namesTemplate  *toolsRender.TextTemplate
	processors     *common.Processors
}

type TCPSinkObject struct {
	sinkMap common.SinkMap
	tcp     *TCP
}

func (ts *TCPSinkObject) Map() common.SinkMap {
	return ts.sinkMap
}

func (ts *TCPSinkObject) Options() interface{} {
	return ts.tcp.options
}

func (t *TCP) Name() string {
	return "TCP"
}

func (t *TCP) Source() string {
	return t.source
}

func (t *TCP) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		t.logger.Error(err)
		return def
	}
	return s1
}

func (t *TCP) appendAddress(name string, addresses map[string]common.Labels, labels map[string]string, rExclusion *regexp.Regexp) {

	host := strings.TrimSpace(name)
	port := ""

	arr := strings.Split(host, ":")
	if len(arr) == 2 {
		host = strings.TrimSpace(arr[0])
		port = strings.TrimSpace(arr[1])
	}

	if !utils.IsEmpty(port) {
		port = fmt.Sprintf(":%s", port)
	}

	name = fmt.Sprintf("%s%s", host, port)

	keys := common.GetLabelsKeys(addresses)
	if utils.Contains(keys, name) {
		return
	}

	if rExclusion != nil && rExclusion.MatchString(name) {
		return
	}

	addresses[name] = labels
}

func (t *TCP) findAddresses(vectors []*common.PrometheusResponseDataVector) common.LabelsMap {

	ret := make(common.LabelsMap)
	gid := utils.GoRoutineID()

	l := len(vectors)
	t.logger.Debug("[%d] %s: found %d series", gid, t.source, l)
	if len(vectors) == 0 {
		return ret
	}

	rPattern := regexp.MustCompile(t.options.Pattern)
	var rExclusion *regexp.Regexp
	if !utils.IsEmpty(t.options.Exclusion) {
		rExclusion = regexp.MustCompile(t.options.Exclusion)
	}

	for _, v := range vectors {

		if len(v.Labels) < 1 {
			t.logger.Debug("[%d] %s: No labels, min requirements (1): %v", gid, t.source, v.Labels)
			continue
		}

		name := ""
		ident := t.render(t.namesTemplate, t.options.Names, v.Labels)
		if utils.IsEmpty(ident) {
			t.logger.Debug("[%d] %s: No name found in labels, but: %v", gid, t.source, v.Labels)
			continue
		}
		if ident == t.options.Names {
			name = v.Labels[ident]
		} else {
			name = ident
		}

		if !rPattern.MatchString(name) {
			continue
		}

		names := rPattern.FindAllString(name, -1)
		if len(names) == 0 {
			t.appendAddress(name, ret, v.Labels, rExclusion)
			continue
		}

		for _, k := range names {
			t.appendAddress(k, ret, v.Labels, rExclusion)
		}
	}
	return ret
}

func (t *TCP) Discover() {

	t.logger.Debug("%s: TCP discovery by query: %s", t.source, t.options.Query)
	if !utils.IsEmpty(t.options.QueryPeriod) {
		// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
		tm := time.Now().UTC()
		t.prometheusOpts.From = common.ParsePeriodFromNow(t.options.QueryPeriod, tm)
		t.prometheusOpts.To = strconv.Itoa(int(tm.Unix()))
		t.prometheusOpts.Step = t.options.QueryStep
		if utils.IsEmpty(t.prometheusOpts.Step) {
			t.prometheusOpts.Step = "15s"
		}
		t.logger.Debug("%s: TCP discovery range: %s <-> %s", t.source, t.prometheusOpts.From, t.prometheusOpts.To)
	}

	data, err := t.prometheus.CustomGet(t.prometheusOpts)
	if err != nil {
		t.logger.Error(err)
		return
	}

	var res common.PrometheusResponse
	if err := json.Unmarshal(data, &res); err != nil {
		t.logger.Error(err)
		return
	}

	if res.Status != "success" {
		t.logger.Error(res.Status)
		return
	}

	if (res.Data == nil) || (len(res.Data.Result) == 0) {
		t.logger.Error("%s: TCP empty data on response", t.source)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		t.logger.Error("%s: TCP only vector and matrix are allowed", t.source)
		return
	}

	addresses := t.findAddresses(res.Data.Result)
	if len(addresses) == 0 {
		t.logger.Debug("%s: TCP not found any addresses according query", t.source)
		return
	}
	t.logger.Debug("%s: TCP found %d addresses according query. Processing...", t.source, len(addresses))

	t.processors.Process(t, &TCPSinkObject{
		sinkMap: common.ConvertLabelsMapToSinkMap(addresses),
		tcp:     t,
	})
}

func NewTCP(source string, prometheusOptions common.PrometheusOptions, options TCPOptions, observability *common.Observability, processors *common.Processors) *TCP {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: TCP no prometheus URL. Skipped", source)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: TCP no query. Skipped", source)
		return nil
	}

	domainNamesOpts := toolsRender.TemplateOptions{
		Content: options.Names,
		Name:    "tcp-names",
	}
	namesTemplate, err := toolsRender.NewTextTemplate(domainNamesOpts, observability)
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

	return &TCP{
		source:         source,
		prometheus:     toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts: prometheusOpts,
		options:        options,
		logger:         logger,
		observability:  observability,
		namesTemplate:  namesTemplate,
		processors:     processors,
	}
}
