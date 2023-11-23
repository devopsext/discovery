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

type CertOptions struct {
	Query       string
	QueryPeriod string
	QueryStep   string
	Schedule    string
	Pattern     string
	Names       string
	Exclusion   string

	TelegrafConf     string
	TelegrafTemplate string
	TelegrafChecksum bool
	TelegrafOptions  telegraf.InputX509CertOptions
}

type Cert struct {
	name           string
	prometheus     *toolsVendors.Prometheus
	prometheusOpts toolsVendors.PrometheusOptions
	options        CertOptions
	logger         sreCommon.Logger
	observability  *common.Observability
	namesTemplate  *toolsRender.TextTemplate
}

func (c *Cert) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		c.logger.Error(err)
		return def
	}
	return s1
}

// .telegraf/cert-discovery.conf
func (c *Cert) createTelegrafConfigs(names map[string]common.Labels) {

	telegrafConfig := &telegraf.Config{
		Observability: c.observability,
	}
	bs, err := telegrafConfig.GenerateInputX509CertBytes(c.options.TelegrafOptions, names)
	if err != nil {
		c.logger.Error("%s: Cert query error: %s", c.name, err)
		return
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(c.name, c.options.TelegrafTemplate, c.options.TelegrafConf, c.options.TelegrafChecksum, bs, c.logger)
}

func (c *Cert) appendAddress(name string, urls map[string]common.Labels, labels map[string]string, rExclusion *regexp.Regexp) {

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

func (c *Cert) findURLs(vectors []*common.PrometheusResponseDataVector) map[string]common.Labels {

	ret := make(map[string]common.Labels)
	gid := utils.GetRoutineID()

	l := len(vectors)
	c.logger.Debug("[%d] %s: found %d series", gid, c.name, l)
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
			c.logger.Debug("[%d] %s: No labels, min requirements (1): %v", gid, c.name, v.Labels)
			continue
		}

		name := ""
		ident := c.render(c.namesTemplate, c.options.Names, v.Labels)
		if utils.IsEmpty(ident) {
			c.logger.Debug("[%d] %s: No name found in labels, but: %v", gid, c.name, v.Labels)
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

	c.logger.Debug("%s: cert discovery by query: %s", c.name, c.options.Query)
	if !utils.IsEmpty(c.options.QueryPeriod) {
		// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
		t := time.Now().UTC()
		c.prometheusOpts.From = common.ParsePeriodFromNow(c.options.QueryPeriod, t)
		c.prometheusOpts.To = strconv.Itoa(int(t.Unix()))
		c.prometheusOpts.Step = c.options.QueryStep
		if utils.IsEmpty(c.prometheusOpts.Step) {
			c.prometheusOpts.Step = "15s"
		}
		c.logger.Debug("%s: cert discovery range: %s <-> %s", c.name, c.prometheusOpts.From, c.prometheusOpts.To)
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
		c.logger.Error("%s: cert empty data on response", c.name)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		c.logger.Error("%s: cert only vector and matrix are allowed", c.name)
		return
	}

	urls := c.findURLs(res.Data.Result)
	if len(urls) == 0 {
		c.logger.Debug("%s: cert not found any urls according query", c.name)
		return
	}
	c.logger.Debug("%s: cert found %d urls according query", c.name, len(urls))
	c.createTelegrafConfigs(urls)
}

func NewCert(name string, prometheusOptions common.PrometheusOptions, options CertOptions, observability *common.Observability) *Cert {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: Cert no prometheus URL. Skipped", name)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: Cert not query. Skipped", name)
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
		Timeout:  prometheusOptions.Timeout,
		Insecure: prometheusOptions.Insecure,
		Query:    options.Query,
	}

	return &Cert{
		name:           name,
		prometheus:     toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts: prometheusOpts,
		options:        options,
		logger:         logger,
		observability:  observability,
		namesTemplate:  namesTemplate,
	}
}
