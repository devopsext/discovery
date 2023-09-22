package common

type PrometheusOptions struct {
	Names    string
	URL      string
	Timeout  int
	Insecure bool
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
