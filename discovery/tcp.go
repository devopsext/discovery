package discovery

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/telegraf"
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

	Names     string
	Exclusion string
	NoSSL     string

	TelegrafConf     string
	TelegrafTemplate string
	TelegrafChecksum bool
	TelegrafOptions  telegraf.InputNetResponseOptions
}

type TCP struct {
	name           string
	prometheus     *toolsVendors.Prometheus
	prometheusOpts toolsVendors.PrometheusOptions
	options        TCPOptions
	logger         sreCommon.Logger
	observability  *common.Observability
	namesTemplate  *toolsRender.TextTemplate
}

func (t *TCP) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		t.logger.Error(err)
		return def
	}
	return s1
}

// .telegraf/TCP-discovery.conf
func (t *TCP) createTelegrafConfigs(names map[string]common.Labels) {

	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	bs, err := telegrafConfig.GenerateInputNetResponseBytes(t.options.TelegrafOptions, names, "tcp")
	if err != nil {
		t.logger.Error("%s: TCP query error: %s", t.name, err)
		return
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(t.name, t.options.TelegrafTemplate, t.options.TelegrafConf, t.options.TelegrafChecksum, bs, t.logger)
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

func (t *TCP) findAddresses(vectors []*common.PrometheusResponseDataVector) map[string]common.Labels {

	ret := make(map[string]common.Labels)
	gid := utils.GetRoutineID()

	l := len(vectors)
	t.logger.Debug("[%d] %s: found %d series", gid, t.name, l)
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
			t.logger.Debug("[%d] %s: No labels, min requirements (1): %v", gid, t.name, v.Labels)
			continue
		}

		name := ""
		ident := t.render(t.namesTemplate, t.options.Names, v.Labels)
		if utils.IsEmpty(ident) {
			t.logger.Debug("[%d] %s: No name found in labels, but: %v", gid, t.name, v.Labels)
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

	t.logger.Debug("%s: TCP discovery by query: %s", t.name, t.options.Query)
	if !utils.IsEmpty(t.options.QueryPeriod) {
		// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
		tm := time.Now().UTC()
		t.prometheusOpts.From = common.ParsePeriodFromNow(t.options.QueryPeriod, tm)
		t.prometheusOpts.To = strconv.Itoa(int(tm.Unix()))
		t.prometheusOpts.Step = t.options.QueryStep
		if utils.IsEmpty(t.prometheusOpts.Step) {
			t.prometheusOpts.Step = "15s"
		}
		t.logger.Debug("%s: TCP discovery range: %s <-> %s", t.name, t.prometheusOpts.From, t.prometheusOpts.To)
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
		t.logger.Error("%s: TCP empty data on response", t.name)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		t.logger.Error("%s: TCP only vector and matrix are allowed", t.name)
		return
	}

	addresses := t.findAddresses(res.Data.Result)
	if len(addresses) == 0 {
		t.logger.Debug("%s: TCP not found any addresses according query", t.name)
		return
	}
	t.logger.Debug("%s: TCP found %d addresses according query", t.name, len(addresses))
	t.createTelegrafConfigs(addresses)
}

func NewTCP(name string, prometheusOptions common.PrometheusOptions, options TCPOptions, observability *common.Observability) *TCP {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: TCP no prometheus URL. Skipped", name)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: TCP no query. Skipped", name)
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
		Timeout:  prometheusOptions.Timeout,
		Insecure: prometheusOptions.Insecure,
		Query:    options.Query,
	}

	return &TCP{
		name:           name,
		prometheus:     toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts: prometheusOpts,
		options:        options,
		logger:         logger,
		observability:  observability,
		namesTemplate:  namesTemplate,
	}
}
