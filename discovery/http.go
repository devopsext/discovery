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

type HTTPOptions struct {
	Query       string
	QueryPeriod string
	QueryStep   string
	Schedule    string
	Pattern     string
	Names       string
	Exclusion   string
	NoSSL       string
	Path        string
}

type HTTP struct {
	source         string
	prometheus     *toolsVendors.Prometheus
	prometheusOpts toolsVendors.PrometheusOptions
	options        HTTPOptions
	logger         sreCommon.Logger
	observability  *common.Observability
	namesTemplate  *toolsRender.TextTemplate
	pathTemplate   *toolsRender.TextTemplate
	sinks          *common.Sinks
}

type HTTPSinkObject struct {
	sinkMap common.SinkMap
	http    *HTTP
}

func (hs *HTTPSinkObject) Map() common.SinkMap {
	return hs.sinkMap
}

func (hs *HTTPSinkObject) Options() interface{} {
	return hs.http.options
}

func (hs *HTTPSinkObject) Slice() []interface{} {
	return common.ConvertLabelMapToSlice(common.ConvertSyncMapToLabelsMap(hs.sinkMap))
}

func (h *HTTP) Name() string {
	return "HTTP"
}

func (h *HTTP) Source() string {
	return h.source
}

func (h *HTTP) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		h.logger.Error(err)
		return def
	}
	return s1
}

func (h *HTTP) appendURL(name string, urls map[string]common.Labels, labels map[string]string, rExclusion, rNoSSL *regexp.Regexp) {

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
	if !utils.IsEmpty(h.options.Path) {
		path = h.render(h.pathTemplate, h.options.Path, labels)
		path = strings.TrimLeft(path, "/")
		if !utils.IsEmpty(path) {
			path = fmt.Sprintf("/%s", path)
		}
	}

	name = fmt.Sprintf("%s://%s%s%s", proto, host, port, path)

	keys := common.GetLabelsKeys(urls)
	if utils.Contains(keys, name) {
		return
	}

	if rExclusion != nil && rExclusion.MatchString(name) {
		return
	}

	urls[name] = labels
}

func (h *HTTP) findURLs(vectors []*common.PrometheusResponseDataVector) common.LabelsMap {

	ret := make(common.LabelsMap)
	gid := utils.GoRoutineID()

	l := len(vectors)
	h.logger.Debug("[%d] %s: found %d series", gid, h.source, l)
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
			h.logger.Debug("[%d] %s: No labels, min requirements (1): %v", gid, h.source, v.Labels)
			continue
		}

		name := ""
		ident := h.render(h.namesTemplate, h.options.Names, v.Labels)
		if utils.IsEmpty(ident) {
			h.logger.Debug("[%d] %s: No name found in labels, but: %v", gid, h.source, v.Labels)
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

	h.logger.Debug("%s: HTTP discovery by query: %s", h.source, h.options.Query)
	if !utils.IsEmpty(h.options.QueryPeriod) {
		// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
		t := time.Now().UTC()
		h.prometheusOpts.From = common.ParsePeriodFromNow(h.options.QueryPeriod, t)
		h.prometheusOpts.To = strconv.Itoa(int(t.Unix()))
		h.prometheusOpts.Step = h.options.QueryStep
		if utils.IsEmpty(h.prometheusOpts.Step) {
			h.prometheusOpts.Step = "15s"
		}
		h.logger.Debug("%s: HTTP discovery range: %s <-> %s", h.source, h.prometheusOpts.From, h.prometheusOpts.To)
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
		h.logger.Error("%s: HTTP empty data on response", h.source)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		h.logger.Error("%s: HTTP only vector and matrix are allowed", h.source)
		return
	}

	urls := h.findURLs(res.Data.Result)
	if len(urls) == 0 {
		h.logger.Debug("%s: HTTP not found any urls according query", h.source)
		return
	}
	h.logger.Debug("%s: HTTP found %d urls according query. Processing...", h.source, len(urls))

	h.sinks.Process(h, &HTTPSinkObject{
		sinkMap: common.ConvertLabelsMapToSinkMap(urls),
		http:    h,
	})
}

func NewHTTP(source string, prometheusOptions common.PrometheusOptions, options HTTPOptions, observability *common.Observability, sinks *common.Sinks) *HTTP {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: HTTP no prometheus URL. Skipped", source)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: HTTP not query. Skipped", source)
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
		Content: options.Path,
		Name:    "http-path",
	}
	pathTemplate, err := toolsRender.NewTextTemplate(pathOpts, observability)
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

	return &HTTP{
		source:         source,
		prometheus:     toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts: prometheusOpts,
		options:        options,
		logger:         logger,
		observability:  observability,
		namesTemplate:  namesTemplate,
		pathTemplate:   pathTemplate,
		sinks:          sinks,
	}
}
