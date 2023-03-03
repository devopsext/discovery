package common

import (
	"bufio"
	"bytes"

	"github.com/BurntSushi/toml"
)

type TelegrafInputPrometheusHttpMetric struct {
	Name     string            `toml:"name"`
	Query    string            `toml:"query"`
	UniqueBy []string          `toml:"unique_by,omitempty"`
	Tags     map[string]string `toml:"tags,omitempty"`
}

type TelegrafInputPrometheusHttpAvailability struct {
	Name     string            `toml:"name"`
	Query    string            `toml:"query"`
	UniqueBy []string          `toml:"unique_by,omitempty"`
	Tags     map[string]string `toml:"tags,omitempty"`
}

type TelegrafInputPrometheusHttp struct {
	URL           string                                     `toml:"url"`
	Version       string                                     `toml:"version"`
	Params        string                                     `toml:"params"`
	Interval      string                                     `toml:"interval"`
	Timeout       string                                     `toml:"timeout"`
	Duration      string                                     `toml:"duration"`
	Prefix        string                                     `toml:"prefix"`
	Metric        []*TelegrafInputPrometheusHttpMetric       `toml:"metric"`
	Availability  []*TelegrafInputPrometheusHttpAvailability `toml:"metric"`
	Tags          map[string]string                          `toml:"tags,omitempty"`
	Include       []string                                   `toml:"taginclude,omitempty"`
	SkipEmptyTags bool                                       `toml:"skip_empty_tags"`
}

type TelegrafInputs struct {
	PrometheusHttp []*TelegrafInputPrometheusHttp `toml:"prometheus_http,omitempty"`
}

type TelegrafConfig struct {
	Inputs TelegrafInputs `toml:"inputs"`
}

//[[inputs.prometheus_http]]
//  [inputs.prometheus_http.tags]
//  [[inputs.prometheus_http.metric]]
//    [inputs.prometheus_http.metric.tags]

func (tc *TelegrafConfig) GenerateServiceConfig(s *Service, path string) ([]byte, error) {

	input := &TelegrafInputPrometheusHttp{}
	/*input.URL = IfDef(productConfig.URL, DEFAULT_PROMETHEUS_URL).(string)
	input.Version = IfDef(productConfig.Version, DEFAULT_VERSION).(string)
	input.Params = IfDef(productConfig.Params, DEFAULT_PARAMS).(string)
	input.Interval = IfDef(productConfig.Interval, DEFAULT_INTERVAL).(string)
	input.Timeout = IfDef(productConfig.Timeout, DEFAULT_TIMEOUT).(string)
	input.Duration = IfDef(productConfig.Duration, DEFAULT_DURATION).(string)
	input.Prefix = IfDef(productConfig.Prefix, DEFAULT_PREFIX).(string)
	input.Tags = make(map[string]string)
	input.SkipEmptyTags = true

	// adding metric
	for _, v := range serviceConfig.Metrics {
		m, err := getMetricInput(serviceConfig, v)
		if err == nil {
			input.updateIncludeTags(getKeys(m.Tags))
			input.Metric = append(input.Metric, m)
		}
	}

	input.updateIncludeTags(productConfig.Include)
	*/
	tc.Inputs.PrometheusHttp = append(tc.Inputs.PrometheusHttp, input)

	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	if err := toml.NewEncoder(w).Encode(tc); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
