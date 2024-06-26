package discovery

import (
	"encoding/json"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type ObserviumDevice struct {
	Name   string `json:"sysName"`
	Host   string `json:"hostname"`
	IP     string `json:"ip"`
	Vendor string `json:"vendor"`
}

type ObserviumDeviceResponse struct {
	Status  string                     `json:"status"`
	Count   int                        `json:"count"`
	Devices map[string]ObserviumDevice `json:"devices"`
}

type ObserviumOptions struct {
	toolsVendors.ObserviumOptions
	Schedule string
}

type Observium struct {
	client        *toolsVendors.Observium
	options       ObserviumOptions
	logger        sreCommon.Logger
	observability *common.Observability
	processors    *common.Processors
}

type ObserviumSinkObject struct {
	sinkMap   common.SinkMap
	observium *Observium
}

func (os *ObserviumSinkObject) Map() common.SinkMap {
	return os.sinkMap
}

func (os *ObserviumSinkObject) Options() interface{} {
	return os.observium.options
}

func (o *Observium) Name() string {
	return "Observium"
}

func (o *Observium) Source() string {
	return ""
}

func (o *Observium) makeDevicesSinkMap(devices map[string]ObserviumDevice) common.SinkMap {

	r := make(common.SinkMap)

	for _, v := range devices {

		common.AppendHostSink(r, v.Name, common.HostSink{
			IP:     v.IP,
			Server: v.Host,
			Vendor: v.Vendor,
		})
	}
	return r
}

func (o *Observium) Discover() {

	o.logger.Debug("Observium discovery by URL: %s", o.options.URL)

	data, err := o.client.CustomGetDevices(o.options.ObserviumOptions)
	if err != nil {
		o.logger.Error(err)
		return
	}

	var res ObserviumDeviceResponse
	if err := json.Unmarshal(data, &res); err != nil {
		o.logger.Error(err)
		return
	}

	if res.Status != "ok" {
		o.logger.Error(res.Status)
		return
	}

	l := len(res.Devices)
	if l == 0 {
		o.logger.Debug("Observium has no devices")
	}

	devices := o.makeDevicesSinkMap(res.Devices)
	o.logger.Debug("Observium found %d devices. Processing...", len(devices))

	o.processors.Process(o, &ObserviumSinkObject{
		sinkMap:   devices,
		observium: o,
	})
}

func NewObservium(options ObserviumOptions, observability *common.Observability, processors *common.Processors) *Observium {

	logger := observability.Logs()

	if utils.IsEmpty(options.URL) {
		logger.Debug("Observium has no URL. Skipped")
		return nil
	}

	return &Observium{
		client:        toolsVendors.NewObservium(options.ObserviumOptions),
		options:       options,
		logger:        logger,
		observability: observability,
		processors:    processors,
	}
}
