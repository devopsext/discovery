package telegraf

import (
	"bufio"
	"bytes"
	"fmt"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"github.com/pkg/errors"
)

type Inputs struct {
	PrometheusHttp []*InputPrometheusHttp `toml:"prometheus_http,omitempty"`
	DNSQuery       []*InputDNSQuery       `toml:"dns_query,omitempty"`
	HTTPResponse   []*InputHTTPResponse   `toml:"http_response,omitempty"`
	NetResponse    []*InputNetResponse    `toml:"net_response,omitempty"`
	X509Cert       []*InputX509Cert       `toml:"x509_cert,omitempty"`
}

type Config struct {
	Inputs        Inputs                `toml:"inputs"`
	Observability *common.Observability `toml:"-"`
}

func (tc *Config) CreateWithTemplateIfCheckSumIsDifferent(name, template, conf string, checksum bool, bs []byte, logger sreCommon.Logger) {

	if bs == nil || (len(bs) == 0) {
		logger.Debug("%s: No query config", name)
		return
	}

	if !utils.IsEmpty(template) {
		bs = bytes.Join([][]byte{bs, []byte(template)}, []byte("\n"))
	}

	exists, err := common.FileWriteWithCheckSum(conf, bs, checksum)
	if err != nil {
		logger.Debug("%s: Cannot create file %s error: %s", name, conf, err)
		return
	}

	if exists {
		logger.Debug("%s: File %s exists, skipped", name, conf)
		return
	}

	logger.Debug("%s: File %s created or replaced", name, conf)
}

func (tc *Config) CreateIfCheckSumIsDifferent(name, conf string, checksum bool, bs []byte, logger sreCommon.Logger) {
	tc.CreateWithTemplateIfCheckSumIsDifferent(name, "", conf, checksum, bs, logger)
}

func (tc *Config) GenerateInputPrometheusHttpBytes(s *common.Object, labelsTpl string,
	opts InputPrometheusHttpOptions, name string, persistMetrics bool) ([]byte, error) {

	input := &InputPrometheusHttp{
		observability: tc.Observability,
	}
	input.Name = name
	input.URL = opts.URL
	input.User = opts.User
	input.Password = opts.Password
	input.Version = opts.Version
	input.Params = opts.Params
	input.CollectionOffset, _ = randomizeOffsetDuration(opts.CollectionOffset)
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
		//labels := common.MergeStringMaps(c.Labels, s.Labels)
		labels := c.Labels
		vars := common.MergeStringMaps(c.Vars, s.Vars)

		input.buildQualities(s, c.Qualities, labelsTpl, opts, labels, vars, fl, persistMetrics)
		input.buildAvailability(s, c.Availability, labelsTpl, opts, labels, vars, fl, persistMetrics)
		input.buildMetrics(s, c.Metrics, labelsTpl, opts, labels, vars, fl, persistMetrics)
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

	servers := make([]string, 0)
	arr := strings.Split(opts.Servers, ",")
	for _, s := range arr {
		s := strings.TrimSpace(s)
		if !utils.Contains(servers, s) {
			servers = append(servers, s)
		}
	}

	sort.Strings(servers)

	keys := common.GetLabelsKeys(domains)
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

	keys := common.GetLabelsKeys(urls)
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
		input.InsecureSkipVerify = true

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

func (tc *Config) GenerateInputNETResponseBytes(opts InputNetResponseOptions, addresses map[string]common.Labels, protocol string) ([]byte, error) {

	keys := common.GetLabelsKeys(addresses)
	sort.Strings(keys)

	for _, k := range keys {
		input := &InputNetResponse{
			observability: tc.Observability,
		}
		input.Interval = opts.Interval
		input.Address = k
		input.Protocol = protocol
		input.Timeout = opts.Timeout
		input.ReadTimeout = opts.ReadTimeout
		input.Send = opts.Send
		input.Expect = opts.Expect

		input.updateIncludeTags(opts.Tags)
		sort.Strings(input.Include)

		input.Tags = addresses[k]
		tc.Inputs.NetResponse = append(tc.Inputs.NetResponse, input)
	}

	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	if err := toml.NewEncoder(w).Encode(tc); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func (tc *Config) GenerateInputX509CertBytes(opts InputX509CertOptions, addresses map[string]common.Labels) ([]byte, error) {

	keys := common.GetLabelsKeys(addresses)
	sort.Strings(keys)

	for _, k := range keys {
		input := &InputX509Cert{
			observability: tc.Observability,
		}
		input.Interval = opts.Interval
		input.Sources = []string{k}
		input.Timeout = opts.Timeout
		input.ServerName = opts.ServerName
		input.ExcludeRootCerts = opts.ExcludeRootCerts
		input.TLSCA = opts.TLSCA
		input.TLSCert = opts.TLSCert
		input.TLSKey = opts.TLSKey
		input.TLSServerName = opts.TLSServerName
		input.UseProxy = opts.UseProxy
		input.ProxyURL = opts.ProxyURL

		input.updateIncludeTags(opts.Tags)
		sort.Strings(input.Include)

		input.Tags = addresses[k]
		tc.Inputs.X509Cert = append(tc.Inputs.X509Cert, input)
	}

	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	if err := toml.NewEncoder(w).Encode(tc); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

func randomizeOffsetDuration(durationStr string) (string, error) {
	if !strings.HasSuffix(durationStr, "s") {
		return "0s", fmt.Errorf("Invalid duration format: %s, must end with 's'", durationStr)
	}

	numStr := strings.TrimSuffix(durationStr, "s")
	maxValue, err := strconv.Atoi(numStr)
	if err != nil {
		return "0s", fmt.Errorf("Invalid numerical value in duration: %w", err)
	}

	if maxValue < 0 {
		return "0s", fmt.Errorf("Duration value cannot be negative: %d", maxValue)
	}

	// skip rest
	if maxValue == 0 {
		return "0s", nil
	}

	// Create a new random number generator with a unique seed
	source := rand.NewSource(time.Now().UnixNano())
	r := rand.New(source)

	// Generate a random integer between 0 (inclusive) and maxValue (inclusive)
	randomValue := r.Intn(maxValue + 1)

	return fmt.Sprintf("%ds", randomValue), nil
}
