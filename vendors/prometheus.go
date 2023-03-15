package vendors

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/tools/vendors"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"gopkg.in/yaml.v2"
)

type PrometheusDiscoveryOptions struct {
	URL          string
	Timeout      int
	Insecure     bool
	Query        string
	Metric       string
	Service      string
	Schedule     string
	BaseTemplate string
	Vars         string

	TelegrafLabels   string
	TelegrafTemplate string
	TelegrafChecksum bool
	TelegrafOptions  common.TelegrafConfigOptions
}

type PrometheusDiscovery struct {
	prometheus       *toolsVendors.Prometheus
	options          PrometheusDiscoveryOptions
	logger           sreCommon.Logger
	serviceTemplate  *toolsRender.TextTemplate
	metricTemplate   *toolsRender.TextTemplate
	telegrafTemplate *toolsRender.TextTemplate
	labelsTemplate   *toolsRender.TextTemplate
	varsTemplate     *toolsRender.TextTemplate
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
		pd.logger.Error("No base templates by pattern: %s", pd.options.BaseTemplate)
		return configs
	}

	for _, v := range files {

		pd.logger.Debug("Processing base config: %s...", v)
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
		pd.logger.Debug("Base config is loaded: %s", v)
	}
	return configs
}

// .telegraf/prefix-{{.namespace}}-discovery-{{.service}}-{{.container_name}}{{.container}}.conf
func (pd *PrometheusDiscovery) createTelegrafConfigs(services map[string]*common.Service) {

	for k, s := range services {

		labels := pd.render(pd.labelsTemplate, pd.options.TelegrafLabels, s.Vars)
		s.Labels = utils.MapGetKeyValues(labels)
		for i, v := range s.Labels {
			if utils.IsEmpty(v) {
				s.Labels[i] = s.Vars[i]
			}
		}

		path := pd.render(pd.telegrafTemplate, pd.options.TelegrafTemplate, s.Vars)
		pd.logger.Debug("Processing service: %s for path: %s", k, path)

		telegrafConfig := &common.TelegrafConfig{}
		bytes, err := telegrafConfig.GenerateServiceBytes(s, pd.options.TelegrafOptions)
		if err != nil {
			pd.logger.Error(err)
			continue
		}

		if bytes == nil || (len(bytes) == 0) {
			pd.logger.Debug("No service config for %s", k)
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
					pd.logger.Debug("File %s has the same md5 hash: %s, skipped", path, fileHashString)
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
		pd.logger.Debug("File %s created with md5 hash: %s", path, bytesHashString)
	}
}

func (pd *PrometheusDiscovery) findServices(vectors []*PrometheusDiscoveryResponseDataVector) map[string]*common.Service {

	configs := pd.readBaseConfigs()
	matched := make(map[string]*common.Service)

	for _, v := range vectors {

		metric := ""
		service := ""
		if len(v.Labels) < 2 {
			pd.logger.Debug("No labels")
			continue
		}

		vars := pd.render(pd.varsTemplate, pd.options.Vars, v.Labels)
		serviceVars := utils.MapGetKeyValues(vars)
		mergedVars := common.MergeMaps(v.Labels, serviceVars)

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
			pd.logger.Debug("No service or metric found in labels, but: %v", mergedVars)
			continue
		}

		for path, config := range configs {

			ds := matched[service]
			if ds == nil {
				ds = &common.Service{
					Configs: make(map[string]*common.BaseConfig),
					Vars:    make(map[string]string),
				}
			}
			exists := config.MetricExists(metric)
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
			matched[service] = ds
		}
	}
	return matched
}

func (pd *PrometheusDiscovery) Discover() {

	pd.logger.Debug("Prometheus discovery by query: %s", pd.options.Query)

	data, err := pd.prometheus.Get()
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
		pd.logger.Error("Empty data on response")
		return
	}

	if res.Data.ResultType != "vector" {
		pd.logger.Error("Only vectors are allowed")
		return
	}

	services := pd.findServices(res.Data.Result)
	if len(services) == 0 {
		pd.logger.Debug("Not found any bases according query")
		return
	}
	pd.createTelegrafConfigs(services)
}

func NewPrometheusDiscovery(options PrometheusDiscoveryOptions, observability *common.Observability) *PrometheusDiscovery {

	logger := observability.Logs()

	varsOpts := toolsRender.TemplateOptions{
		Content: options.Vars,
	}
	varsTemplate, err := toolsRender.NewTextTemplate(varsOpts, observability)
	if err != nil {
		logger.Error(err)
	}

	metricOpts := toolsRender.TemplateOptions{
		Content: options.Metric,
	}
	metricTemplate, err := toolsRender.NewTextTemplate(metricOpts, observability)
	if err != nil {
		logger.Error(err)
	}

	serviceOpts := toolsRender.TemplateOptions{
		Content: options.Service,
	}
	serviceTemplate, err := toolsRender.NewTextTemplate(serviceOpts, observability)
	if err != nil {
		logger.Error(err)
	}

	labelsOpts := toolsRender.TemplateOptions{
		Content: options.TelegrafLabels,
	}
	labelsTemplate, err := toolsRender.NewTextTemplate(labelsOpts, observability)
	if err != nil {
		logger.Error(err)
	}

	telegrafOpts := toolsRender.TemplateOptions{
		Content: options.TelegrafTemplate,
	}
	telegrafTemplate, err := toolsRender.NewTextTemplate(telegrafOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	return &PrometheusDiscovery{
		prometheus: vendors.NewPrometheus(vendors.PrometheusOptions{
			URL:      options.URL,
			Timeout:  options.Timeout,
			Insecure: options.Insecure,
			Query:    options.Query,
		}),
		options:          options,
		logger:           logger,
		serviceTemplate:  serviceTemplate,
		metricTemplate:   metricTemplate,
		telegrafTemplate: telegrafTemplate,
		labelsTemplate:   labelsTemplate,
		varsTemplate:     varsTemplate,
		//services: observability.Metrics().Counter("services", "Count of all found services", []string{}, "prometheus"),
	}
}
