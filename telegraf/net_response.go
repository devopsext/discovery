package telegraf

import "github.com/devopsext/discovery/common"

// https://github.com/influxdata/telegraf/blob/release-1.25/plugins/inputs/net_response/README.md
//[[inputs.net_response]]

type InputNetResponse struct {
	Interval      string            `toml:"interval,omitempty"`
	Address       string            `toml:"address"`
	Protocol      string            `toml:"protocol"`
	Timeout       string            `toml:"timeout,omitempty"`
	ReadTimeout   string            `toml:"read_timeout,omitempty"`
	Send          string            `toml:"send,omitempty"`
	Expect        string            `toml:"expect,omitempty"`
	Tags          map[string]string `toml:"tags,omitempty"`
	Include       []string          `toml:"taginclude,omitempty"`
	observability *common.Observability
}

type InputNetResponseOptions struct {
	Interval    string
	Address     string
	Protocol    string
	Timeout     string
	ReadTimeout string
	Send        string
	Expect      string
	Tags        []string
}

func (nr *InputNetResponse) updateIncludeTags(tags []string) {

	for _, tag := range tags {
		if !common.StringInArr(tag, nr.Include) {
			nr.Include = append(nr.Include, tag)
		}
	}
}
