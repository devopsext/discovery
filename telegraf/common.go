package telegraf

import (
	"bufio"
	"bytes"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/devopsext/discovery/common"
	"github.com/devopsext/utils"
	"github.com/pkg/errors"
)

type Inputs struct {
	PrometheusHttp []*InputPrometheusHttp `toml:"prometheus_http,omitempty"`
	DNSQuery       []*InputDNSQuery       `toml:"dns_query,omitempty"`
	HTTPResponse   []*InputHTTPResponse   `toml:"http_response,omitempty"`
}

type Config struct {
	Inputs        Inputs                `toml:"inputs"`
	Observability *common.Observability `toml:"-"`
}

func (tc *Config) GenerateInputPrometheusHttpBytes(s *common.Service, labelsTpl string,
	opts InputPrometheusHttpOptions, name string) ([]byte, error) {

	input := &InputPrometheusHttp{
		observability: tc.Observability,
	}
	input.Name = name
	input.URL = opts.URL
	input.Version = opts.Version
	input.Params = opts.Params
	input.Interval = opts.Interval
	input.Timeout = opts.Timeout
	input.Duration = opts.Duration
	input.Prefix = opts.Prefix
	input.Tags = make(map[string]string)
	input.SkipEmptyTags = true

	fl := make(map[string]interface{})

	fkeys := common.GetFileKeys(s.Files)
	sort.Strings(fkeys)

	for _, k := range fkeys {
		v := s.Files[k]
		f := &InputPrometheusHttpFile{
			Name: k,
			Path: v.Path,
			Type: v.Type,
		}
		input.File = append(input.File, f)
		fl[k] = v.Obj
	}

	keys := common.GetBaseConfigKeys(s.Configs)
	sort.Strings(keys)

	for _, k := range keys {

		c := s.Configs[k]
		labels := common.MergeStringMaps(c.Labels, s.Labels)
		vars := common.MergeStringMaps(c.Vars, s.Vars)

		input.buildQualities(s, c.Qualities, labelsTpl, opts, labels, vars, fl)
		input.buildAvailability(s, c.Availability, labelsTpl, opts, labels, vars, fl)
		input.buildMetrics(s, c.Metrics, labelsTpl, opts, labels, vars, fl)
	}

	if len(input.Metric) == 0 {
		return nil, errors.New("Metrics are not found.")
	}

	input.updateIncludeTags(opts.DefaultTags)
	sort.Strings(input.Include)

	tc.Inputs.PrometheusHttp = append(tc.Inputs.PrometheusHttp, input)

	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	if err := toml.NewEncoder(w).Encode(tc); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (tc *Config) GenerateInputDNSQueryBytes(opts InputDNSQueryOptions, domains map[string]common.Labels) ([]byte, error) {

	servers := []string{}
	arr := strings.Split(opts.Servers, ",")
	for _, s := range arr {
		s := strings.TrimSpace(s)
		if !utils.Contains(servers, s) {
			servers = append(servers, s)
		}
	}

	sort.Strings(servers)

	keys := common.GetDomainKeys(domains)
	sort.Strings(keys)

	for _, k := range keys {
		input := &InputDNSQuery{
			observability: tc.Observability,
		}
		input.Interval = opts.Interval
		input.Servers = servers
		input.Domains = []string{k}
		input.Network = opts.Network
		input.RecordType = opts.RecordType
		input.Port = opts.Port
		input.Timeout = opts.Timeout

		input.updateIncludeTags(opts.Tags)
		sort.Strings(input.Include)

		input.Tags = domains[k]
		tc.Inputs.DNSQuery = append(tc.Inputs.DNSQuery, input)
	}

	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	if err := toml.NewEncoder(w).Encode(tc); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (tc *Config) GenerateInputHTTPResponseBytes(opts InputHTTPResponseOptions, urls map[string]common.Labels) ([]byte, error) {

	keys := common.GetDomainKeys(urls)
	sort.Strings(keys)

	for _, k := range keys {
		input := &InputHTTPResponse{
			observability: tc.Observability,
		}
		input.Interval = opts.Interval
		input.URLs = []string{k}
		input.Timeout = opts.Timeout
		input.Method = opts.Method
		input.FollowRedirects = opts.FollowRedirects
		input.StringMatch = opts.StringMatch
		input.StatusCode = opts.StatusCode

		input.updateIncludeTags(opts.Tags)
		sort.Strings(input.Include)

		input.Tags = urls[k]
		tc.Inputs.HTTPResponse = append(tc.Inputs.HTTPResponse, input)
	}

	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	if err := toml.NewEncoder(w).Encode(tc); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
