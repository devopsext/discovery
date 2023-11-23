package telegraf

import "github.com/devopsext/discovery/common"

// https://github.com/influxdata/telegraf/blob/release-1.25/plugins/inputs/x509_cert/README.md
//[[inputs.x509_cert]]

type InputX509Cert struct {
	Interval         string            `toml:"interval,omitempty"`
	Sources          []string          `toml:"sources"`
	Timeout          string            `toml:"timeout,omitempty"`
	ServerName       string            `toml:"server_name,omitempty"`
	ExcludeRootCerts bool              `toml:"exclude_root_certs,omitempty"`
	TLSCA            string            `toml:"tls_ca,omitempty"`
	TLSCert          string            `toml:"tls_cert,omitempty"`
	TLSKey           string            `toml:"tls_key,omitempty"`
	TLSServerName    string            `toml:"tls_server_name,omitempty"`
	UseProxy         bool              `toml:"use_proxy,omitempty"`
	ProxyURL         string            `toml:"proxy_url,omitempty"`
	Tags             map[string]string `toml:"tags,omitempty"`
	Include          []string          `toml:"taginclude,omitempty"`
	observability    *common.Observability
}

type InputX509CertOptions struct {
	Interval         string
	Sources          string
	Timeout          string
	ServerName       string
	ExcludeRootCerts bool
	TLSCA            string
	TLSCert          string
	TLSKey           string
	TLSServerName    string
	UseProxy         bool
	ProxyURL         string
	Tags             []string
}

func (xc *InputX509Cert) updateIncludeTags(tags []string) {

	for _, tag := range tags {
		if !common.StringInArr(tag, xc.Include) {
			xc.Include = append(xc.Include, tag)
		}
	}
}
