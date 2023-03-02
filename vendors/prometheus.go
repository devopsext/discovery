package vendors

type PrometheusDiscoveryOptions struct {
	URL      string
	Timeout  int
	Insecure bool
	Query    string
}

type PrometheusDiscovery struct {
}
