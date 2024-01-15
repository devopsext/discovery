package discovery

import (
	"encoding/json"
	"fmt"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type ZabbixHostInterface struct {
	IP  string `json:"ip"`
	Dns string `json:"dns"`
}

type ZabbixHost struct {
	Name       string                 `json:"name"`
	Host       string                 `json:"host"`
	Inventory  any                    `json:"inventory"`
	Interfaces []*ZabbixHostInterface `json:"interfaces"`
}

type ZabbixHostGetResponse struct {
	Result []*ZabbixHost `json:"result"`
}

type ZabbixOptions struct {
	toolsVendors.ZabbixOptions
	Schedule string
}

type Zabbix struct {
	client        *toolsVendors.Zabbix
	options       ZabbixOptions
	logger        sreCommon.Logger
	observability *common.Observability
	sinks         *common.Sinks
}

type ZabbixSinkObject struct {
	sinkMap common.SinkMap
	Zabbix  *Zabbix
}

func (os *ZabbixSinkObject) Map() common.SinkMap {
	return os.sinkMap
}

func (os *ZabbixSinkObject) Options() interface{} {
	return os.Zabbix.options
}

func (o *Zabbix) Name() string {
	return "Zabbix"
}

func (o *Zabbix) Source() string {
	return ""
}

func (o *ZabbixHost) inventoryIsMap() (map[string]interface{}, bool) {
	if utils.IsEmpty(o.Inventory) {
		return nil, false
	}
	_, ok := o.Inventory.([]any)
	if ok {
		return nil, false
	}
	m, ok := o.Inventory.(map[string]interface{})
	return m, ok
}

func (o *ZabbixHost) getOS() string {
	m, ok := o.inventoryIsMap()
	if ok {
		return fmt.Sprintf("%s", m["os"])
	}
	return ""
}

func (o *ZabbixHost) getVendor() string {
	m, ok := o.inventoryIsMap()
	if ok {
		return fmt.Sprintf("%s", m["vendor"])
	}
	return ""
}

func (o *ZabbixHost) getIP() string {
	if len(o.Interfaces) == 0 {
		return ""
	}
	ip := ""
	for _, v := range o.Interfaces {
		if !utils.IsEmpty(v.IP) {
			ip = v.IP
			break
		}
	}
	return ip
}

func (o *ZabbixHost) getHost(host string) string {
	if len(o.Interfaces) == 0 {
		return ""
	}
	dns := host
	for _, v := range o.Interfaces {
		if !utils.IsEmpty(v.Dns) {
			dns = v.Dns
			break
		}
	}
	return dns
}

func (o *Zabbix) makeHostsSinkMap(hosts []*ZabbixHost) common.SinkMap {

	r := make(common.SinkMap)

	for _, v := range hosts {

		common.AppendHostSink(r, v.Name, common.HostSink{
			IP:     v.getIP(),
			Host:   v.getHost(v.Host),
			Vendor: v.getVendor(),
			OS:     v.getOS(),
		})
	}
	return r
}

func (o *Zabbix) Discover() {

	o.logger.Debug("Zabbix discovery by URL: %s", o.options.URL)

	opts := toolsVendors.ZabbixHostOptions{
		Fields:     []string{"name", "host"},
		Inventory:  []string{"os", "vendor"},
		Interfaces: []string{"ip", "dns"},
	}

	data, err := o.client.CustomGetHosts(o.options.ZabbixOptions, opts)
	if err != nil {
		o.logger.Error(err)
		return
	}

	var res ZabbixHostGetResponse
	if err := json.Unmarshal(data, &res); err != nil {
		o.logger.Error(err)
		return
	}

	l := len(res.Result)
	if l == 0 {
		o.logger.Debug("Zabbix has no hosts")
	}

	hosts := o.makeHostsSinkMap(res.Result)
	o.logger.Debug("Zabbix found %d hosts. Processing...", len(hosts))

	o.sinks.Process(o, &ZabbixSinkObject{
		sinkMap: hosts,
		Zabbix:  o,
	})
}

func NewZabbix(options ZabbixOptions, observability *common.Observability, sinks *common.Sinks) *Zabbix {

	logger := observability.Logs()

	if utils.IsEmpty(options.URL) {
		logger.Debug("Zabbix has no URL. Skipped")
		return nil
	}

	return &Zabbix{
		client:        toolsVendors.NewZabbix(options.ZabbixOptions),
		options:       options,
		logger:        logger,
		observability: observability,
		sinks:         sinks,
	}
}
