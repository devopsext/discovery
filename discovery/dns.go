package discovery

import (
	"encoding/json"
	"net"
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

type DNSOptions struct {
	Query       string
	QueryPeriod string
	QueryStep   string
	Schedule    string
	Pattern     string
	Names       string
	Exclusion   string
	Source      string
}

type DNS struct {
	source              string
	prometheus          *toolsVendors.Prometheus
	prometheusOpts      toolsVendors.PrometheusOptions
	options             DNSOptions
	logger              sreCommon.Logger
	observability       *common.Observability
	domainNamesTemplate *toolsRender.TextTemplate
	processors          *common.Processors
}

type DNSSinkObject struct {
	sinkMap common.SinkMap
	dns     *DNS
}

func (ds *DNSSinkObject) Map() common.SinkMap {
	return ds.sinkMap
}

func (ds *DNSSinkObject) Options() interface{} {
	return ds.dns.options
}

func (d *DNS) Name() string {
	return "DNS"
}

func (d *DNS) Source() string {
	return d.source
}

func (d *DNS) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		d.logger.Error(err)
		return def
	}
	return s1
}

func (d *DNS) appendDomain(name string, domains map[string]common.Labels, labels map[string]string, rExclusion *regexp.Regexp) {

	ipOrHost := strings.TrimSpace(name)

	arr := strings.Split(ipOrHost, ":")
	if len(arr) == 2 {
		ipOrHost = strings.TrimSpace(arr[0])
	}

	keys := common.GetLabelsKeys(domains)
	if utils.Contains(keys, ipOrHost) {
		return
	}

	a := net.ParseIP(ipOrHost)
	if a != nil {
		return
	}

	if rExclusion != nil && rExclusion.MatchString(ipOrHost) {
		return
	}
	domains[ipOrHost] = labels
}

func (d *DNS) findDomains(vectors []*common.PrometheusResponseDataVector) common.LabelsMap {

	ret := make(common.LabelsMap)
	gid := utils.GoRoutineID()

	l := len(vectors)
	d.logger.Debug("[%d] %s: found %d series", gid, d.source, l)
	if len(vectors) == 0 {
		return ret
	}

	rPattern := regexp.MustCompile(d.options.Pattern)
	var rExclusion *regexp.Regexp
	if !utils.IsEmpty(d.options.Exclusion) {
		rExclusion = regexp.MustCompile(d.options.Exclusion)
	}

	for _, v := range vectors {

		if len(v.Labels) < 1 {
			d.logger.Debug("[%d] %s: No labels, min requirements (1): %v", gid, d.source, v.Labels)
			continue
		}

		domain := ""
		ident := d.render(d.domainNamesTemplate, d.options.Names, v.Labels)
		if utils.IsEmpty(ident) {
			d.logger.Debug("[%d] %s: No doman found in labels, but: %v", gid, d.source, v.Labels)
			continue
		}
		if ident == d.options.Names {
			domain = v.Labels[ident]
		} else {
			domain = ident
		}

		if !rPattern.MatchString(domain) {
			continue
		}

		domains := rPattern.FindAllString(domain, -1)
		if len(domains) == 0 {
			d.appendDomain(domain, ret, v.Labels, rExclusion)
			continue
		}

		for _, k := range domains {
			d.appendDomain(k, ret, v.Labels, rExclusion)
		}
	}
	return ret
}

func (d *DNS) Discover() {

	d.logger.Debug("%s: DNS discovery by query: %s", d.source, d.options.Query)
	if !utils.IsEmpty(d.options.QueryPeriod) {
		// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
		t := time.Now().UTC()
		d.prometheusOpts.From = common.ParsePeriodFromNow(d.options.QueryPeriod, t)
		d.prometheusOpts.To = strconv.Itoa(int(t.Unix()))
		d.prometheusOpts.Step = d.options.QueryStep
		if utils.IsEmpty(d.prometheusOpts.Step) {
			d.prometheusOpts.Step = "15s"
		}
		d.logger.Debug("%s: DNS discovery range: %s <-> %s", d.source, d.prometheusOpts.From, d.prometheusOpts.To)
	}

	data, err := d.prometheus.CustomGet(d.prometheusOpts)
	if err != nil {
		d.logger.Error(err)
		return
	}

	var res common.PrometheusResponse
	if err := json.Unmarshal(data, &res); err != nil {
		d.logger.Error(err)
		return
	}

	if res.Status != "success" {
		d.logger.Error(res.Status)
		return
	}

	if (res.Data == nil) || (len(res.Data.Result) == 0) {
		d.logger.Error("%s: DNS empty data on response", d.source)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		d.logger.Error("%s: DNS only vector and matrix are allowed", d.source)
		return
	}

	domains := d.findDomains(res.Data.Result)
	if len(domains) == 0 {
		d.logger.Debug("%s: DNS not found any domains according query", d.source)
		return
	}
	d.logger.Debug("%s: DNS found %d domains according query. Processing...", d.source, len(domains))

	d.processors.Process(d, &DNSSinkObject{
		sinkMap: common.ConvertLabelsMapToSinkMap(domains),
		dns:     d,
	})
}

func NewDNS(source string, prometheusOptions common.PrometheusOptions, options DNSOptions, observability *common.Observability, processors *common.Processors) *DNS {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: DNS no prometheus URL. Skipped", source)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: DNS no query. Skipped", source)
		return nil
	}

	domainNamesOpts := toolsRender.TemplateOptions{
		Content: options.Names,
		Name:    "dns-names",
	}
	domainNamesTemplate, err := toolsRender.NewTextTemplate(domainNamesOpts, observability)
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

	return &DNS{
		source:              source,
		prometheus:          toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts:      prometheusOpts,
		options:             options,
		logger:              logger,
		observability:       observability,
		domainNamesTemplate: domainNamesTemplate,
		processors:          processors,
	}
}
