package telegraf

import "github.com/devopsext/discovery/common"

// https://github.com/influxdata/telegraf/blob/release-1.25/plugins/inputs/dns_query/README.md
//[[inputs.dns_query]]

type InputDNSQuery struct {
	Interval      string            `toml:"interval,omitempty"`
	Servers       []string          `toml:"servers"`
	Network       string            `toml:"network,omitempty"`
	Domains       []string          `toml:"domains"`
	RecordType    string            `toml:"record_type,omitempty"`
	Port          int               `toml:"port,omitempty"`
	Timeout       int               `toml:"timeout,omitempty"`
	Tags          map[string]string `toml:"tags,omitempty"`
	Include       []string          `toml:"taginclude,omitempty"`
	observability *common.Observability
}

type InputDNSQueryConfigOptions struct {
	Interval   string
	Servers    string
	Network    string
	Domains    string
	RecordType string
	Port       int
	Timeout    int
	Tags       []string
}

func (dq *InputDNSQuery) updateIncludeTags(tags []string) {

	for _, tag := range tags {
		if !common.StringInArr(tag, dq.Include) {
			dq.Include = append(dq.Include, tag)
		}
	}
}
