package telegraf

import "github.com/devopsext/discovery/common"

// https://github.com/influxdata/telegraf/blob/release-1.25/plugins/inputs/http_response/README.md
//[[inputs.dns_query]]

type InputHTTPResponse struct {
	Interval        string            `toml:"interval,omitempty"`
	URLs            []string          `toml:"urls"`
	Timeout         string            `toml:"response_timeout,omitempty"`
	Method          string            `toml:"method,omitempty"`
	FollowRedirects bool              `toml:"follow_redirects,omitempty"`
	StringMatch     string            `toml:"response_string_match,omitempty"`
	StatusCode      int               `toml:"response_status_code,omitempty"`
	Tags            map[string]string `toml:"tags,omitempty"`
	Include         []string          `toml:"taginclude,omitempty"`
	observability   *common.Observability
}

type InputHTTPResponseOptions struct {
	Interval        string
	URLs            string
	Method          string
	FollowRedirects bool
	StringMatch     string
	StatusCode      int
	Timeout         string
	Tags            []string
}

func (hr *InputHTTPResponse) updateIncludeTags(tags []string) {

	for _, tag := range tags {
		if !common.StringInArr(tag, hr.Include) {
			hr.Include = append(hr.Include, tag)
		}
	}
}
