package discovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/telegraf"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type DNSOptions struct {
	Query         string
	QueryPeriod   string
	QueryStep     string
	Schedule      string
	DomainPattern string
	DomainNames   string

	TelegrafConf     string
	TelegrafTemplate string
	TelegrafChecksum bool
	TelegrafOptions  telegraf.InputDNSQueryConfigOptions
}

type DNS struct {
	name                string
	prometheus          *toolsVendors.Prometheus
	prometheusOpts      toolsVendors.PrometheusOptions
	options             DNSOptions
	logger              sreCommon.Logger
	observability       *common.Observability
	domainNamesTemplate *toolsRender.TextTemplate
}

func (d *DNS) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		d.logger.Error(err)
		return def
	}
	return s1
}

// .telegraf/dns-discovery.conf
func (d *DNS) createTelegrafConfigs(domains map[string]common.Labels) {

	telegrafConfig := &telegraf.Config{
		Observability: d.observability,
	}
	bs, err := telegrafConfig.GenerateInputDNSQueryBytes(d.options.TelegrafOptions, domains)
	if err != nil {
		d.logger.Error("%s: DNS query error: %s", d.name, err)
		return
	}

	if bs == nil || (len(bs) == 0) {
		d.logger.Debug("%s: No DNS query config", d.name)
		return
	}

	if !utils.IsEmpty(d.options.TelegrafTemplate) {
		bs = bytes.Join([][]byte{bs, []byte(d.options.TelegrafTemplate)}, []byte("\n"))
	}

	bytesHashString := ""
	bytesHash := common.ByteMD5(bs)
	if bytesHash != nil {
		bytesHashString = fmt.Sprintf("%x", bytesHash)
	}

	path := d.options.TelegrafConf
	if d.options.TelegrafChecksum {

		if _, err := os.Stat(path); err == nil {
			fileHashString := ""
			fileHash := common.FileMD5(path)
			if fileHash != nil {
				fileHashString = fmt.Sprintf("%x", fileHash)
			}

			if fileHashString == bytesHashString {
				d.logger.Debug("%s: File %s has the same md5 hash: %s, skipped", d.name, path, fileHashString)
				return
			}
		}
	}

	dir := filepath.Dir(path)
	if _, err = os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			d.logger.Error(err)
			return
		}
	}

	f, err := os.Create(path)
	if err != nil {
		d.logger.Error(err)
		return
	}
	defer f.Close()

	_, err = f.Write(bs)
	if err != nil {
		d.logger.Error(err)
		return
	}
	d.logger.Debug("%s: File %s created with md5 hash: %s", d.name, path, bytesHashString)
}

func (d *DNS) findDomains(vectors []*common.PrometheusResponseDataVector) map[string]common.Labels {

	ret := make(map[string]common.Labels)
	gid := utils.GetRoutineID()

	l := len(vectors)
	d.logger.Debug("[%d] %s: found %d series", gid, d.name, l)
	if len(vectors) == 0 {
		return ret
	}

	r := regexp.MustCompile(d.options.DomainPattern)
	for _, v := range vectors {

		if len(v.Labels) < 1 {
			d.logger.Debug("[%d] %s: No labels, min requirements (1): %v", gid, d.name, v.Labels)
			continue
		}

		domain := ""
		ident := d.render(d.domainNamesTemplate, d.options.DomainNames, v.Labels)
		if utils.IsEmpty(ident) {
			d.logger.Debug("[%d] %s: No doman found in labels, but: %v", gid, d.name, v.Labels)
			continue
		}
		if ident == d.options.DomainNames {
			domain = v.Labels[ident]
		} else {
			domain = ident
		}

		if !r.MatchString(domain) {
			continue
		}

		a := net.ParseIP(domain)
		if a != nil {
			continue
		}

		if utils.Contains(r, domain) {
			continue
		}
		ret[domain] = v.Labels
	}
	return ret
}

func (d *DNS) Discover() {

	d.logger.Debug("%s: DNS discovery by query: %s", d.name, d.options.Query)
	if !utils.IsEmpty(d.options.QueryPeriod) {
		// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
		t := time.Now().UTC()
		d.prometheusOpts.From = common.ParsePeriodFromNow(d.options.QueryPeriod, t)
		d.prometheusOpts.To = strconv.Itoa(int(t.Unix()))
		d.prometheusOpts.Step = d.options.QueryStep
		if utils.IsEmpty(d.prometheusOpts.Step) {
			d.prometheusOpts.Step = "15s"
		}
		d.logger.Debug("%s: DNS discovery range: %s <-> %s", d.name, d.prometheusOpts.From, d.prometheusOpts.To)
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
		d.logger.Error("%s: Empty data on response", d.name)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		d.logger.Error("%s: Only vector and matrix are allowed", d.name)
		return
	}

	domains := d.findDomains(res.Data.Result)
	if len(domains) == 0 {
		d.logger.Debug("%s: Not found any domains according query", d.name)
		return
	}
	d.logger.Debug("%s: Found %d domains according query", d.name, len(domains))
	d.createTelegrafConfigs(domains)
}

func NewDNS(name string, prometheusOptions common.PrometheusOptions, options DNSOptions, observability *common.Observability) *DNS {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: No prometheus URL. Skipped", name)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: No DNS query. Skipped", name)
		return nil
	}

	domainNamesOpts := toolsRender.TemplateOptions{
		Content: options.DomainNames,
		Name:    "dns-domain-names",
	}
	domainNamesTemplate, err := toolsRender.NewTextTemplate(domainNamesOpts, observability)
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

	return &DNS{
		name:                name,
		prometheus:          toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts:      prometheusOpts,
		options:             options,
		logger:              logger,
		observability:       observability,
		domainNamesTemplate: domainNamesTemplate,
	}
}
