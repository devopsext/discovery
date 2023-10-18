package common

type PromDiscoveryObject struct {
	Name         string
	URL          string
	HttpUsername string
	HttpPassword string
}

type PrometheusOptions struct {
	Names        string
	URL          string
	HttpUsername string
	HttpPassword string
	Timeout      int
	Insecure     bool
}

type PrometheusResponseDataVector struct {
	Labels map[string]string `json:"metric"`
}

type PrometheusResponseData struct {
	ResultType string                          `json:"resultType"`
	Result     []*PrometheusResponseDataVector `json:"result"`
}

type PrometheusResponse struct {
	Status string                  `json:"status"`
	Data   *PrometheusResponseData `json:"data"`
}
