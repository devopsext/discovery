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

type CertOptions struct {
	Query       string
	QueryPeriod string
	QueryStep   string
	Schedule    string
	Pattern     string
	Names       string
	Exclusion   string
}

type Cert struct {
	source         string
	prometheus     *toolsVendors.Prometheus
	prometheusOpts toolsVendors.PrometheusOptions
	options        CertOptions
	logger         sreCommon.Logger
	observability  *common.Observability
	namesTemplate  *toolsRender.TextTemplate
	sinks          *common.Sinks
}

type CertSinkObject struct {
	sinkMap common.SinkMap
	cert    *Cert
}

func (cs *CertSinkObject) Map() common.SinkMap {
	return cs.sinkMap
}

func (cs *CertSinkObject) Options() interface{} {
	return cs.cert.options
}

func (c *Cert) Name() string {
	return "Cert"
}

func (c *Cert) Source() string {
	return c.source
}

func (c *Cert) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		c.logger.Error(err)
		return def
	}
	return s1
}

func (c *Cert) appendAddress(name string, urls common.LabelsMap, labels map[string]string, rExclusion *regexp.Regexp) {

	proto := ""
	host := ""
	port := ""

	arr := strings.Split(name, "://")
	if len(arr) == 2 {
		host = strings.TrimSpace(arr[1])
	} else {
		host = name
	}

	arr = strings.Split(host, ":")
	if len(arr) == 2 {
		host = strings.TrimSpace(arr[0])
		port = strings.TrimSpace(arr[1])
	}

	if labels["scope"] == "http_out" {
		if !utils.IsEmpty(port) && port != "443" {
			return
		}
		proto = "https"
		port = fmt.Sprintf(":%s", "443")
	} else {
		if utils.IsEmpty(port) {
			return
		}
		proto = "tcp"
		port = fmt.Sprintf(":%s", port)
	}

	name = fmt.Sprintf("%s://%s%s", proto, host, port)

	keys := common.GetLabelsKeys(urls)
	if utils.Contains(keys, name) {
		return
	}

	if rExclusion != nil && rExclusion.MatchString(name) {
		return
	}

	urls[name] = labels
}

func (c *Cert) findURLs(vectors []*common.PrometheusResponseDataVector) common.LabelsMap {

	ret := make(common.LabelsMap)
	gid := utils.GetRoutineID()

	l := len(vectors)
	c.logger.Debug("[%d] %s: found %d series", gid, c.source, l)
	if len(vectors) == 0 {
		return ret
	}

	rPattern := regexp.MustCompile(c.options.Pattern)
	var rExclusion *regexp.Regexp
	if !utils.IsEmpty(c.options.Exclusion) {
		rExclusion = regexp.MustCompile(c.options.Exclusion)
	}

	for _, v := range vectors {

		if len(v.Labels) < 1 {
			c.logger.Debug("[%d] %s: No labels, min requirements (1): %v", gid, c.source, v.Labels)
			continue
		}

		name := ""
		ident := c.render(c.namesTemplate, c.options.Names, v.Labels)
		if utils.IsEmpty(ident) {
			c.logger.Debug("[%d] %s: No name found in labels, but: %v", gid, c.source, v.Labels)
			continue
		}
		if ident == c.options.Names {
			name = v.Labels[ident]
		} else {
			name = ident
		}

		if !rPattern.MatchString(name) {
			continue
		}

		names := rPattern.FindAllString(name, -1)
		if len(names) == 0 {
			c.appendAddress(name, ret, v.Labels, rExclusion)
			continue
		}

		for _, k := range names {
			c.appendAddress(k, ret, v.Labels, rExclusion)
		}
	}
	return ret
}

func (c *Cert) Discover() {

	c.logger.Debug("%s: cert discovery by query: %s", c.source, c.options.Query)
	if !utils.IsEmpty(c.options.QueryPeriod) {
		// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
		t := time.Now().UTC()
		c.prometheusOpts.From = common.ParsePeriodFromNow(c.options.QueryPeriod, t)
		c.prometheusOpts.To = strconv.Itoa(int(t.Unix()))
		c.prometheusOpts.Step = c.options.QueryStep
		if utils.IsEmpty(c.prometheusOpts.Step) {
			c.prometheusOpts.Step = "15s"
		}
		c.logger.Debug("%s: cert discovery range: %s <-> %s", c.source, c.prometheusOpts.From, c.prometheusOpts.To)
	}

	data, err := c.prometheus.CustomGet(c.prometheusOpts)
	if err != nil {
		c.logger.Error(err)
		return
	}

	var res common.PrometheusResponse
	if err := json.Unmarshal(data, &res); err != nil {
		c.logger.Error(err)
		return
	}

	if res.Status != "success" {
		c.logger.Error(res.Status)
		return
	}

	if (res.Data == nil) || (len(res.Data.Result) == 0) {
		c.logger.Error("%s: cert empty data on response", c.source)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		c.logger.Error("%s: cert only vector and matrix are allowed", c.source)
		return
	}

	urls := c.findURLs(res.Data.Result)
	if len(urls) == 0 {
		c.logger.Debug("%s: cert not found any urls according query", c.source)
		return
	}
	c.logger.Debug("%s: cert found %d urls according query. Processing...", c.source, len(urls))

	c.sinks.Process(c, &CertSinkObject{
		sinkMap: common.ConvertLabelsMapToSinkMap(urls),
		cert:    c,
	})
}

func NewCert(source string, prometheusOptions common.PrometheusOptions, options CertOptions, observability *common.Observability, sinks *common.Sinks) *Cert {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: Cert no prometheus URL. Skipped", source)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: Cert not query. Skipped", source)
		return nil
	}

	namesOpts := toolsRender.TemplateOptions{
		Content: options.Names,
		Name:    "cert-names",
	}
	namesTemplate, err := toolsRender.NewTextTemplate(namesOpts, observability)
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

	return &Cert{
		source:         source,
		prometheus:     toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts: prometheusOpts,
		options:        options,
		logger:         logger,
		observability:  observability,
		namesTemplate:  namesTemplate,
		sinks:          sinks,
	}
}
