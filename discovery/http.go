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

type HTTPOptions struct {
	Query       string
	QueryPeriod string
	QueryStep   string
	Schedule    string
	Pattern     string
	Names       string
	Exclusion   string
	NoSSL       string

	TelegrafConf     string
	TelegrafTemplate string
	TelegrafChecksum bool
	TelegrafOptions  telegraf.InputHTTPResponseOptions
}

type HTTP struct {
	name           string
	prometheus     *toolsVendors.Prometheus
	prometheusOpts toolsVendors.PrometheusOptions
	options        HTTPOptions
	logger         sreCommon.Logger
	observability  *common.Observability
	namesTemplate  *toolsRender.TextTemplate
	pathTemplate   *toolsRender.TextTemplate
}

func (h *HTTP) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		h.logger.Error(err)
		return def
	}
	return s1
}

// .telegraf/HTTP-discovery.conf
func (h *HTTP) createTelegrafConfigs(names map[string]common.Labels) {

	telegrafConfig := &telegraf.Config{
		Observability: h.observability,
	}
	bs, err := telegrafConfig.GenerateInputHTTPResponseBytes(h.options.TelegrafOptions, names)
	if err != nil {
		h.logger.Error("%s: HTTP query error: %s", h.name, err)
		return
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(h.name, h.options.TelegrafTemplate, h.options.TelegrafConf, h.options.TelegrafChecksum, bs, h.logger)
}

func (h *HTTP) appendURL(name string, urls map[string]common.Labels, labels map[string]string, rExclusion, rNoSSL *regexp.Regexp) {

	keys := common.GetLabelsKeys(urls)
	if utils.Contains(keys, name) {
		return
	}

	if rExclusion != nil && rExclusion.MatchString(name) {
		return
	}

	proto := "https"
	if rNoSSL != nil && rNoSSL.MatchString(name) {
		proto = "http"
	}

	host := ""
	arr := strings.Split(name, "://")
	if len(arr) == 2 {
		proto = strings.TrimSpace(arr[0])
		host = strings.TrimSpace(arr[1])
	} else {
		host = name
	}
	port := ""

	arr = strings.Split(host, ":")
	if len(arr) == 2 {
		host = strings.TrimSpace(arr[0])
		port = strings.TrimSpace(arr[1])
	}

	if !utils.IsEmpty(port) {
		if port == "80" || port == "443" {
			port = ""
		}
	}

	if !utils.IsEmpty(port) {
		port = fmt.Sprintf(":%s", port)
	}

	path := ""
	if !utils.IsEmpty(h.options.TelegrafOptions.Path) {
		path = h.render(h.pathTemplate, h.options.TelegrafOptions.Path, labels)
		path = strings.TrimLeft(path, "/")
		if !utils.IsEmpty(path) {
			path = fmt.Sprintf("/%s", path)
		}
	}

	name = fmt.Sprintf("%s://%s%s%s", proto, host, port, path)
	urls[name] = labels
}

func (h *HTTP) findURLs(vectors []*common.PrometheusResponseDataVector) map[string]common.Labels {

	ret := make(map[string]common.Labels)
	gid := utils.GetRoutineID()

	l := len(vectors)
	h.logger.Debug("[%d] %s: found %d series", gid, h.name, l)
	if len(vectors) == 0 {
		return ret
	}

	rPattern := regexp.MustCompile(h.options.Pattern)
	var rExclusion *regexp.Regexp
	if !utils.IsEmpty(h.options.Exclusion) {
		rExclusion = regexp.MustCompile(h.options.Exclusion)
	}
	var rNoSSL *regexp.Regexp
	if !utils.IsEmpty(h.options.NoSSL) {
		rNoSSL = regexp.MustCompile(h.options.NoSSL)
	}

	for _, v := range vectors {

		if len(v.Labels) < 1 {
			h.logger.Debug("[%d] %s: No labels, min requirements (1): %v", gid, h.name, v.Labels)
			continue
		}

		name := ""
		ident := h.render(h.namesTemplate, h.options.Names, v.Labels)
		if utils.IsEmpty(ident) {
			h.logger.Debug("[%d] %s: No name found in labels, but: %v", gid, h.name, v.Labels)
			continue
		}
		if ident == h.options.Names {
			name = v.Labels[ident]
		} else {
			name = ident
		}

		if !rPattern.MatchString(name) {
			continue
		}

		names := rPattern.FindAllString(name, -1)
		if len(names) == 0 {
			h.appendURL(name, ret, v.Labels, rExclusion, rNoSSL)
			continue
		}

		for _, k := range names {
			h.appendURL(k, ret, v.Labels, rExclusion, rNoSSL)
		}
	}
	return ret
}

func (h *HTTP) Discover() {

	h.logger.Debug("%s: HTTP discovery by query: %s", h.name, h.options.Query)
	if !utils.IsEmpty(h.options.QueryPeriod) {
		// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
		t := time.Now().UTC()
		h.prometheusOpts.From = common.ParsePeriodFromNow(h.options.QueryPeriod, t)
		h.prometheusOpts.To = strconv.Itoa(int(t.Unix()))
		h.prometheusOpts.Step = h.options.QueryStep
		if utils.IsEmpty(h.prometheusOpts.Step) {
			h.prometheusOpts.Step = "15s"
		}
		h.logger.Debug("%s: HTTP discovery range: %s <-> %s", h.name, h.prometheusOpts.From, h.prometheusOpts.To)
	}

	data, err := h.prometheus.CustomGet(h.prometheusOpts)
	if err != nil {
		h.logger.Error(err)
		return
	}

	var res common.PrometheusResponse
	if err := json.Unmarshal(data, &res); err != nil {
		h.logger.Error(err)
		return
	}

	if res.Status != "success" {
		h.logger.Error(res.Status)
		return
	}

	if (res.Data == nil) || (len(res.Data.Result) == 0) {
		h.logger.Error("%s: HTTP empty data on response", h.name)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		h.logger.Error("%s: HTTP only vector and matrix are allowed", h.name)
		return
	}

	urls := h.findURLs(res.Data.Result)
	if len(urls) == 0 {
		h.logger.Debug("%s: HTTP not found any urls according query", h.name)
		return
	}
	h.logger.Debug("%s: HTTP found %d urls according query", h.name, len(urls))
	h.createTelegrafConfigs(urls)
}

func NewHTTP(name string, prometheusOptions common.PrometheusOptions, options HTTPOptions, observability *common.Observability) *HTTP {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: HTTP no prometheus URL. Skipped", name)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: HTTP not query. Skipped", name)
		return nil
	}

	namesOpts := toolsRender.TemplateOptions{
		Content: options.Names,
		Name:    "http-names",
	}
	namesTemplate, err := toolsRender.NewTextTemplate(namesOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	pathOpts := toolsRender.TemplateOptions{
		Content: options.TelegrafOptions.Path,
		Name:    "http-path",
	}
	pathTemplate, err := toolsRender.NewTextTemplate(pathOpts, observability)
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

	return &HTTP{
		name:           name,
		prometheus:     toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts: prometheusOpts,
		options:        options,
		logger:         logger,
		observability:  observability,
		namesTemplate:  namesTemplate,
		pathTemplate:   pathTemplate,
	}
}
