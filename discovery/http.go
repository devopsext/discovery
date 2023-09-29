package discovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
func (h *HTTP) createTelegrafConfigs(domains map[string]common.Labels) {

	telegrafConfig := &telegraf.Config{
		Observability: h.observability,
	}
	bs, err := telegrafConfig.GenerateInputHTTPResponseBytes(h.options.TelegrafOptions, domains)
	if err != nil {
		h.logger.Error("%s: HTTP query error: %s", h.name, err)
		return
	}

	if bs == nil || (len(bs) == 0) {
		h.logger.Debug("%s: No HTTP query config", h.name)
		return
	}

	if !utils.IsEmpty(h.options.TelegrafTemplate) {
		bs = bytes.Join([][]byte{bs, []byte(h.options.TelegrafTemplate)}, []byte("\n"))
	}

	bytesHashString := ""
	bytesHash := common.ByteMD5(bs)
	if bytesHash != nil {
		bytesHashString = fmt.Sprintf("%x", bytesHash)
	}

	path := h.options.TelegrafConf
	if h.options.TelegrafChecksum {

		if _, err := os.Stat(path); err == nil {
			fileHashString := ""
			fileHash := common.FileMD5(path)
			if fileHash != nil {
				fileHashString = fmt.Sprintf("%x", fileHash)
			}

			if fileHashString == bytesHashString {
				h.logger.Debug("%s: File %s has the same md5 hash: %s, skipped", h.name, path, fileHashString)
				return
			}
		}
	}

	dir := filepath.Dir(path)
	if _, err = os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			h.logger.Error(err)
			return
		}
	}

	f, err := os.Create(path)
	if err != nil {
		h.logger.Error(err)
		return
	}
	defer f.Close()

	_, err = f.Write(bs)
	if err != nil {
		h.logger.Error(err)
		return
	}
	h.logger.Debug("%s: File %s created with md5 hash: %s", h.name, path, bytesHashString)
}

func (h *HTTP) appendURL(name string, urls map[string]common.Labels, labels map[string]string, rExclusion, rNoSSL *regexp.Regexp) {

	if utils.Contains(urls, name) {
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
		port = fmt.Sprintf(":%s", port)
	}
	name = fmt.Sprintf("%s://%s%s", proto, host, port)
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
		h.logger.Error("%s: Empty data on response", h.name)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		h.logger.Error("%s: Only vector and matrix are allowed", h.name)
		return
	}

	urls := h.findURLs(res.Data.Result)
	if len(urls) == 0 {
		h.logger.Debug("%s: Not found any urls according query", h.name)
		return
	}
	h.logger.Debug("%s: Found %d urls according query", h.name, len(urls))
	h.createTelegrafConfigs(urls)
}

func NewHTTP(name string, prometheusOptions common.PrometheusOptions, options HTTPOptions, observability *common.Observability) *HTTP {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: No prometheus URL. Skipped", name)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: No HTTP query. Skipped", name)
		return nil
	}

	domainNamesOpts := toolsRender.TemplateOptions{
		Content: options.Names,
		Name:    "http-names",
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

	return &HTTP{
		name:           name,
		prometheus:     toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts: prometheusOpts,
		options:        options,
		logger:         logger,
		observability:  observability,
		namesTemplate:  namesTemplate,
	}
}
