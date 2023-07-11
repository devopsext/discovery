package vendors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"gopkg.in/yaml.v2"
)

type PrometheusDiscoveryOptions struct {
	Names        string
	URL          string
	Timeout      int
	Insecure     bool
	Query        string
	QueryPeriod  string
	QueryStep    string
	Metric       string
	Service      string
	Disabled     []string
	Schedule     string
	BaseTemplate string
	Vars         string
	Files        string

	TelegrafLabels   string
	TelegrafTemplate string
	TelegrafChecksum bool
	TelegrafOptions  common.TelegrafConfigOptions
}

type PrometheusDiscovery struct {
	name              string
	prometheus        *toolsVendors.Prometheus
	prometheusOptions toolsVendors.PrometheusOptions
	options           PrometheusDiscoveryOptions
	logger            sreCommon.Logger
	observability     *common.Observability
	serviceTemplate   *toolsRender.TextTemplate
	metricTemplate    *toolsRender.TextTemplate
	telegrafTemplate  *toolsRender.TextTemplate
	varsTemplate      *toolsRender.TextTemplate
	// services   sreCommon.Counter
}

type PrometheusDiscoveryResponseDataVector struct {
	Labels map[string]string `json:"metric"`
}

type PrometheusDiscoveryResponseData struct {
	ResultType string                                   `json:"resultType"`
	Result     []*PrometheusDiscoveryResponseDataVector `json:"result"`
}

type PrometheusDiscoveryResponse struct {
	Status string                           `json:"status"`
	Data   *PrometheusDiscoveryResponseData `json:"data"`
}

func (pd *PrometheusDiscovery) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		pd.logger.Error(err)
		return def
	}
	return s
}

// ".templates/SRE/service-*.yml"
func (pd *PrometheusDiscovery) readBaseConfigs() map[string]*common.BaseConfig {

	configs := make(map[string]*common.BaseConfig)

	files, err := filepath.Glob(pd.options.BaseTemplate)
	if err != nil {
		pd.logger.Error(err)
		return configs
	}

	if len(files) == 0 {
		pd.logger.Error("%s: No base templates by pattern: %s", pd.name, pd.options.BaseTemplate)
		return configs
	}

	for _, v := range files {

		pd.logger.Debug("%s: Processing base config: %s...", pd.name, v)
		content, err := os.ReadFile(v)
		if err != nil {
			pd.logger.Error(err)
			continue
		}

		config := &common.BaseConfig{}
		err = yaml.Unmarshal(content, config)
		if err != nil {
			pd.logger.Error(err)
			continue
		}
		configs[v] = config
		pd.logger.Debug("%s: Base config is loaded: %s", pd.name, v)
	}
	return configs
}

// .telegraf/prefix-{{.namespace}}-discovery-{{.service}}-{{.container_name}}{{.container}}.conf
func (pd *PrometheusDiscovery) createTelegrafConfigs(services map[string]*common.Service) {

	for k, s := range services {

		path := pd.render(pd.telegrafTemplate, pd.options.TelegrafTemplate, s.Vars)
		pd.logger.Debug("%s: Processing service: %s for path: %s", pd.name, k, path)

		telegrafConfig := &common.TelegrafConfig{
			Observability: pd.observability,
		}
		bytes, err := telegrafConfig.GenerateServiceBytes(s, pd.options.TelegrafLabels, pd.options.TelegrafOptions, path)
		if err != nil {
			pd.logger.Error(err)
			continue
		}

		if bytes == nil || (len(bytes) == 0) {
			pd.logger.Debug("%s: No service config for %s", pd.name, k)
			continue
		}

		bytesHashString := ""
		bytesHash := common.ByteMD5(bytes)
		if bytesHash != nil {
			bytesHashString = fmt.Sprintf("%x", bytesHash)
		}

		if pd.options.TelegrafChecksum {

			if _, err := os.Stat(path); err == nil {
				fileHashString := ""
				fileHash := common.FileMD5(path)
				if fileHash != nil {
					fileHashString = fmt.Sprintf("%x", fileHash)
				}

				if fileHashString == bytesHashString {
					pd.logger.Debug("%s: File %s has the same md5 hash: %s, skipped", pd.name, path, fileHashString)
					continue
				}
			}
		}

		dir := filepath.Dir(path)
		if _, err = os.Stat(dir); os.IsNotExist(err) {
			err := os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				pd.logger.Error(err)
				continue
			}
		}

		f, err := os.Create(path)
		if err != nil {
			pd.logger.Error(err)
			continue
		}
		defer f.Close()

		_, err = f.Write(bytes)
		if err != nil {
			pd.logger.Error(err)
			continue
		}
		pd.logger.Debug("%s: File %s created with md5 hash: %s", pd.name, path, bytesHashString)
	}
}

func (pd *PrometheusDiscovery) readJson(bytes []byte) (interface{}, error) {

	var v interface{}
	err := json.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (pd *PrometheusDiscovery) readToml(bytes []byte) (interface{}, error) {

	return nil, fmt.Errorf("%s: toml is not implemented", pd.name)
}

func (pd *PrometheusDiscovery) readYaml(bytes []byte) (interface{}, error) {

	return nil, fmt.Errorf("%s: yaml is not implemented", pd.name)
}

func (pd *PrometheusDiscovery) readFile(path, typ string) interface{} {

	if _, err := os.Stat(path); err != nil {
		pd.logger.Error(err)
		return nil
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		pd.logger.Error(err)
		return nil
	}

	tp := strings.Replace(filepath.Ext(path), ".", "", 1)
	if typ != "" {
		tp = typ
	}

	var obj interface{}
	switch {
	case tp == "json":
		obj, err = pd.readJson(bytes)
	case tp == "toml":
		obj, err = pd.readToml(bytes)
	case tp == "yaml":
		obj, err = pd.readYaml(bytes)
	default:
		obj, err = pd.readJson(bytes)
	}
	if err != nil {
		pd.logger.Error(err)
		return nil
	}
	return obj
}

func (pd *PrometheusDiscovery) getFiles(vars map[string]string) map[string]*common.File {

	files := make(map[string]*common.File)

	tpl, err := toolsRender.NewTextTemplate(toolsRender.TemplateOptions{Content: pd.options.Files}, pd.observability)
	if err != nil {
		pd.logger.Error(err)
		return files
	}

	fs := pd.render(tpl, pd.options.Files, vars)
	kv := utils.MapGetKeyValues(fs)
	for k, v := range kv {
		if utils.FileExists(v) {
			typ := strings.Replace(filepath.Ext(v), ".", "", 1)
			obj := pd.readFile(v, typ)
			if obj != nil {
				files[k] = &common.File{
					Path: v,
					Type: typ,
					Obj:  obj,
				}
			}
		}
	}
	return files
}

func (pd *PrometheusDiscovery) expandDisabled(files map[string]*common.File, vars map[string]string) []string {

	r := []string{}
	m := make(map[string]interface{})

	fls := make(map[string]interface{})
	for k, v := range files {
		fls[k] = v.Obj
	}
	m["files"] = fls
	m["vars"] = vars

	for _, v := range pd.options.Disabled {

		if utils.FileExists(v) {
			bytes, err := utils.Content(v)
			if err != nil {
				pd.logger.Error(err)
				continue
			}
			tpl, err := toolsRender.NewTextTemplate(toolsRender.TemplateOptions{Content: string(bytes)}, pd.observability)
			if err != nil {
				pd.logger.Error(err)
				continue
			}
			arr := []string{}
			sarr := pd.render(tpl, string(bytes), m)
			if !utils.IsEmpty(sarr) {
				arr = strings.Split(sarr, ",")
			}
			for _, a := range arr {
				if !utils.IsEmpty(a) && !utils.Contains(r, a) {
					r = append(r, a)
				}
			}
		} else {
			if !utils.IsEmpty(v) && !utils.Contains(r, v) {
				r = append(r, v)
			}
		}
	}
	return r
}

func (pd *PrometheusDiscovery) checkDisabled(disabled []string, service string) (bool, string) {

	for _, v := range disabled {

		match, _ := regexp.MatchString(v, service)
		if match {
			return true, v
		}
	}
	return false, ""
}

func (pd *PrometheusDiscovery) findServices(vectors []*PrometheusDiscoveryResponseDataVector) map[string]*common.Service {

	configs := pd.readBaseConfigs()
	matched := make(map[string]*common.Service)

	for _, v := range vectors {

		metric := ""
		service := ""
		if len(v.Labels) < 2 {
			continue
		}

		fls := pd.getFiles(v.Labels)
		m := make(map[string]interface{})
		for k, v := range v.Labels {
			m[k] = v
		}
		files := make(map[string]interface{})
		for k, v := range fls {
			files[k] = v.Obj
		}
		m["files"] = files
		m["source"] = pd.name

		vars := pd.render(pd.varsTemplate, pd.options.Vars, m)
		serviceVars := utils.MapGetKeyValues(vars)
		mergedVars := common.MergeStringMaps(v.Labels, serviceVars)

		if utils.IsEmpty(pd.options.Metric) && (len(v.Labels) > 0) {
			for _, m := range v.Labels {
				metric = m
				break
			}
		} else {
			ident := pd.render(pd.metricTemplate, pd.options.Metric, mergedVars)
			if ident == pd.options.Metric {
				metric = mergedVars[ident]
			} else {
				metric = ident
			}
		}

		if utils.IsEmpty(pd.options.Service) && (len(v.Labels) > 1) {
			flag := false
			for _, m := range v.Labels {
				if flag {
					service = m
					break
				}
				flag = true
			}
		} else {
			ident := pd.render(pd.serviceTemplate, pd.options.Service, mergedVars)
			if ident == pd.options.Service {
				service = mergedVars[ident]
			} else {
				service = ident
			}
		}

		if utils.IsEmpty(service) || utils.IsEmpty(metric) {
			pd.logger.Debug("%s: No service or metric found in labels, but: %v", pd.name, mergedVars)
			continue
		}

		// find service in cmdb
		// if it's disabled, skip it with warning

		disabled := pd.expandDisabled(fls, mergedVars)
		dis, pattern := pd.checkDisabled(disabled, service)
		if dis {
			pd.logger.Debug("%s: Service %s disabled by pattern: %s", pd.name, service, pattern)
			continue
		}

		for path, config := range configs {

			if config.Disbaled {
				continue
			}

			ds := matched[service]
			if ds == nil {
				ds = &common.Service{
					Configs: make(map[string]*common.BaseConfig),
					Vars:    make(map[string]string),
				}
			}
			exists := config.MetricExists(metric, mergedVars)
			if !exists {
				continue
			}

			if ds.Configs[path] == nil {
				ds.Configs[path] = config
			}
			for k, l := range serviceVars {
				if (ds.Vars[k] == "") && (l != metric) {
					ds.Vars[k] = l
				}
			}
			ds.Files = fls
			matched[service] = ds
		}

	}
	return matched
}

func (pd *PrometheusDiscovery) parsePeriodFromNow(t time.Time) string {

	durStr := pd.options.QueryPeriod
	if utils.IsEmpty(durStr) {
		return ""
	}

	if durStr == "" {
		durStr = "0s"
	}

	if durStr == "0d" {
		durStr = "0h"
	}

	dur, err := time.ParseDuration(durStr)
	if err != nil {
		return ""
	}

	from := t.Add(time.Duration(dur))
	return strconv.Itoa(int(from.Unix()))
}

func (pd *PrometheusDiscovery) Discover() {

	pd.logger.Debug("%s: Prometheus discovery by query: %s", pd.name, pd.options.Query)

	if !utils.IsEmpty(pd.options.QueryPeriod) {
		// https://prometheus.io/docs/prometheus/latest/querying/api/#range-queries
		t := time.Now().UTC()
		pd.prometheusOptions.From = pd.parsePeriodFromNow(t)
		pd.prometheusOptions.To = strconv.Itoa(int(t.Unix()))
		pd.prometheusOptions.Step = pd.options.QueryStep
		if utils.IsEmpty(pd.prometheusOptions.Step) {
			pd.prometheusOptions.Step = "15s"
		}
		pd.logger.Debug("%s: Prometheus discovery range: %s <-> %s", pd.name, pd.prometheusOptions.From, pd.prometheusOptions.To)
	}

	data, err := pd.prometheus.CustomGet(pd.prometheusOptions)
	if err != nil {
		pd.logger.Error(err)
		return
	}

	var res PrometheusDiscoveryResponse
	if err := json.Unmarshal(data, &res); err != nil {
		pd.logger.Error(err)
		return
	}

	if res.Status != "success" {
		pd.logger.Error(res.Status)
		return
	}

	if (res.Data == nil) || (len(res.Data.Result) == 0) {
		pd.logger.Error("%s: Empty data on response", pd.name)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		pd.logger.Error("%s: Only vector and matrix are allowed", pd.name)
		return
	}

	services := pd.findServices(res.Data.Result)
	if len(services) == 0 {
		pd.logger.Debug("%s: Not found any bases according query", pd.name)
		return
	}
	pd.createTelegrafConfigs(services)
}

func NewPrometheusDiscovery(name string, options PrometheusDiscoveryOptions, observability *common.Observability) *PrometheusDiscovery {

	logger := observability.Logs()

	varsOpts := toolsRender.TemplateOptions{
		Content: options.Vars,
		Name:    "prometheus-vars",
	}
	varsTemplate, err := toolsRender.NewTextTemplate(varsOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	metricOpts := toolsRender.TemplateOptions{
		Content: options.Metric,
		Name:    "prometheus-metrics",
	}
	metricTemplate, err := toolsRender.NewTextTemplate(metricOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	serviceOpts := toolsRender.TemplateOptions{
		Content: options.Service,
		Name:    "prometheus-services",
	}
	serviceTemplate, err := toolsRender.NewTextTemplate(serviceOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	telegrafOpts := toolsRender.TemplateOptions{
		Content: options.TelegrafTemplate,
		Name:    "prometheus-telegraf",
	}
	telegrafTemplate, err := toolsRender.NewTextTemplate(telegrafOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	if utils.IsEmpty(options.URL) {
		logger.Debug("%s: No prometheus URL. Skipped", name)
		return nil
	}

	prometheusOpts := toolsVendors.PrometheusOptions{
		URL:      options.URL,
		Timeout:  options.Timeout,
		Insecure: options.Insecure,
		Query:    options.Query,
	}

	return &PrometheusDiscovery{
		name:              name,
		prometheus:        toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOptions: prometheusOpts,
		options:           options,
		logger:            logger,
		observability:     observability,
		serviceTemplate:   serviceTemplate,
		metricTemplate:    metricTemplate,
		telegrafTemplate:  telegrafTemplate,
		varsTemplate:      varsTemplate,
		//services: observability.Metrics().Counter("services", "Count of all found services", []string{}, "prometheus"),
	}
}
