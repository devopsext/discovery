package common

type ObserviumDevice struct {
	Host   string `json:"hostname"`
	IP     string `json:"ip"`
	Vendor string `json:"vendor"`
}

type ObserviumDeviceResponse struct {
	Status  string                     `json:"status"`
	Count   int                        `json:"count"`
	Devices map[string]ObserviumDevice `json:"devices"`
}
