package telegraf

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

	bytesHashString := ""
	bytesHash := common.ByteMD5(bs)
	if bytesHash != nil {
		bytesHashString = fmt.Sprintf("%x", bytesHash)
	}

	path := conf
	if checksum {

		if _, err := os.Stat(path); err == nil {
			fileHashString := ""
			fileHash := common.FileMD5(path)
			if fileHash != nil {
				fileHashString = fmt.Sprintf("%x", fileHash)
			}

			if fileHashString == bytesHashString {
				logger.Debug("%s: File %s has the same md5 hash: %s, skipped", name, path, fileHashString)
				return
			}
		}
	}

	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			logger.Error(err)
			return
		}
	}

	f, err := os.Create(path)
	if err != nil {
		logger.Error(err)
		return
	}
	defer f.Close()

	_, err = f.Write(bs)
	if err != nil {
		logger.Error(err)
		return
	}
	logger.Debug("%s: File %s created with md5 hash: %s", name, path, bytesHashString)
}

func (tc *Config) CreateIfCheckSumIsDifferent(name, conf string, checksum bool, bs []byte, logger sreCommon.Logger) {
	tc.CreateWithTemplateIfCheckSumIsDifferent(name, "", conf, checksum, bs, logger)
}

func (tc *Config) GenerateInputPrometheusHttpBytes(s *common.Application, labelsTpl string,
	opts InputPrometheusHttpOptions, name string) ([]byte, error) {

	input := &InputPrometheusHttp{
		observability: tc.Observability,
	}
	input.Name = name
	input.URL = opts.URL
	input.User = opts.User
	input.Password = opts.Password
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
		//labels := common.MergeStringMaps(c.Labels, s.Labels)
		labels := c.Labels
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
