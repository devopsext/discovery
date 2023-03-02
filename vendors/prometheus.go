package vendors

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/tools/vendors"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"gopkg.in/yaml.v2"
)

type PrometheusDiscoveryOptions struct {
	URL              string
	Timeout          int
	Insecure         bool
	Query            string
	Metric           string
	Service          string
	Schedule         string
	BaseTemplate     string
	TelegrafTemplate string
}

type PrometheusDiscovery struct {
	prometheus *toolsVendors.Prometheus
	options    PrometheusDiscoveryOptions
	logs       *sreCommon.Logs
}

type PrometheusDiscoveryResponseDataVector struct {
	Metric map[string]string `json:"metric"`
}

type PrometheusDiscoveryResponseData struct {
	ResultType string                                   `json:"resultType"`
	Result     []*PrometheusDiscoveryResponseDataVector `json:"result"`
}

type PrometheusDiscoveryResponse struct {
	Status string                           `json:"status"`
	Data   *PrometheusDiscoveryResponseData `json:"data"`
}

// ".templates/SRE/service-*.yml"
func (pd *PrometheusDiscovery) readBaseConfigs() map[string]*common.BaseConfig {

	configs := make(map[string]*common.BaseConfig)

	files, err := filepath.Glob(pd.options.BaseTemplate)
	if err != nil {
		pd.logs.Error(err)
		return configs
	}

	if len(files) == 0 {
		pd.logs.Error("No base templates by pattern: %s", pd.options.BaseTemplate)
		return configs
	}

	for _, v := range files {

		pd.logs.Debug("Processing file: %s...", v)
		content, err := os.ReadFile(v)
		if err != nil {
			pd.logs.Error(err)
			continue
		}

		config := &common.BaseConfig{}
		err = yaml.Unmarshal(content, config)
		if err != nil {
			pd.logs.Error(err)
			continue
		}
		configs[v] = config
	}
	return configs
}

func (pd *PrometheusDiscovery) processVectors(vectors []*PrometheusDiscoveryResponseDataVector) {

	configs := pd.readBaseConfigs()
	matched := make(map[string][]*common.BaseConfig)

	for _, v := range vectors {

		metric := ""
		service := ""
		if len(v.Metric) < 2 {
			continue
		}

		if utils.IsEmpty(pd.options.Metric) && (len(v.Metric) > 0) {
			for _, m := range v.Metric {
				metric = m
				break
			}
		} else {
			metric = v.Metric[pd.options.Metric]
		}

		if utils.IsEmpty(pd.options.Service) && (len(v.Metric) > 1) {
			flag := false
			for _, m := range v.Metric {
				if flag {
					service = m
					break
				}
				flag = true
			}
		} else {
			service = v.Metric[pd.options.Service]
		}

		if utils.IsEmpty(service) || utils.IsEmpty(metric) {
			continue
		}

		for _, config := range configs {

			arr := matched[service]
			exists := config.MetricExists(metric)
			if len(arr) == 0 && exists {
				arr = append(arr, config)
				matched[service] = arr
				continue
			}

			found := false
			for _, c := range arr {
				if c == config {
					found = true
				}
			}
			if !found && exists {
				arr = append(arr, config)
			}
			matched[service] = arr
		}
	}

	if len(matched) > 0 {
		pd.logs.Debug("test")
	}
}

func (pd *PrometheusDiscovery) Discover() {

	pd.logs.Debug("Prometheus discovery by query: %s", pd.options.Query)

	data, err := pd.prometheus.Get()
	if err != nil {
		pd.logs.Error(err)
		return
	}

	var res PrometheusDiscoveryResponse
	if err := json.Unmarshal(data, &res); err != nil {
		pd.logs.Error(err)
		return
	}

	if res.Status != "success" {
		pd.logs.Error(res.Status)
		return
	}

	if (res.Data == nil) || (len(res.Data.Result) == 0) {
		pd.logs.Error("Empty data on response")
		return
	}

	if res.Data.ResultType != "vector" {
		pd.logs.Error("Only vectors are allowed")
		return
	}
	pd.processVectors(res.Data.Result)
}

func NewPrometheusDiscovery(options PrometheusDiscoveryOptions, observability *common.Observability) *PrometheusDiscovery {
	return &PrometheusDiscovery{
		prometheus: vendors.NewPrometheus(vendors.PrometheusOptions{
			URL:      options.URL,
			Timeout:  options.Timeout,
			Insecure: options.Insecure,
			Query:    options.Query,
		}),
		options: options,
		logs:    observability.Logs(),
	}
}
