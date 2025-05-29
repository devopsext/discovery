package discovery

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type NetboxDevice struct {
	ID         int              `json:"id"`
	Name       string           `json:"name"`
	Display    string           `json:"display"`
	DeviceType NestedNetboxType `json:"device_type"`
	DeviceRole NestedNetbox     `json:"role"`
	Site       NestedNetbox     `json:"site"`
	Rack       NestedNetbox     `json:"rack"`
	Status     Choice           `json:"status"`
	PrimaryIP  NestedIP         `json:"primary_ip"`
}

type NestedNetbox struct {
	ID      int    `json:"id,omitempty"`
	URL     string `json:"url,omitempty"`
	Name    string `json:"name,omitempty"`
	Slug    string `json:"slug,omitempty"`
	Display string `json:"display,omitempty"`
}

type NestedNetboxType struct {
	ID           int    `json:"id,omitempty"`
	URL          string `json:"url,omitempty"`
	Name         string `json:"name,omitempty"`
	Slug         string `json:"slug,omitempty"`
	Display      string `json:"display,omitempty"`
	Manufacturer struct {
		ID          int    `json:"id,omitempty"`
		URL         string `json:"url,omitempty"`
		Display     string `json:"display,omitempty"`
		Name        string `json:"name,omitempty"`
		Slug        string `json:"slug,omitempty"`
		Description string `json:"description,omitempty"`
	} `json:"manufacturer,omitempty"`
}

// Choice represents a field in NetBox that is chosen from a predefined list of options.
type Choice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// NestedIP represents nested IP address fields within a device record.
type NestedIP struct {
	ID      int    `json:"id,omitempty"`
	URL     string `json:"url,omitempty"`
	Address string `json:"address,omitempty"`
}

type NetboxDeviceResponse struct {
	Status  string                  `json:"status"`
	Count   int                     `json:"count"`
	Devices map[string]NetboxDevice `json:"devices"`
}

type NetboxOptions struct {
	toolsVendors.NetboxOptions
	Schedule string
	toolsVendors.NetboxDeviceOptions
}

type Netbox struct {
	client        *toolsVendors.Netbox
	options       NetboxOptions
	logger        sreCommon.Logger
	observability *common.Observability
	processors    *common.Processors
}

type NetboxSinkObject struct {
	sinkMap common.SinkMap
	Netbox  *Netbox
}

func (ns *NetboxSinkObject) Map() common.SinkMap {
	return ns.sinkMap
}

func (ns *NetboxSinkObject) Options() interface{} {
	return ns.Netbox.options
}

func (n *Netbox) Name() string {
	return "Netbox"
}

func (n *Netbox) Source() string {
	return ""
}

func (n *Netbox) makeDevicesSinkMap(devices []NetboxDevice) common.SinkMap {

	r := make(common.SinkMap)

	for _, v := range devices {

		netboxLabels := make(common.Labels)

		ip, _, _ := strings.Cut(v.PrimaryIP.Address, "/")

		netboxLabels["rack"] = v.Rack.Name
		netboxLabels["role"] = v.DeviceRole.Slug
		netboxLabels["site"] = v.Site.Slug

		common.AppendHostSinkLabels(r, v.Name, common.HostSink{
			IP:     ip,
			Host:   v.Name,
			Vendor: v.DeviceType.Manufacturer.Name,
		}, netboxLabels)
	}
	return r
}

func (n *Netbox) Discover() {

	n.logger.Debug("Netbox discovery by URL: %s", n.options.URL)

	data, err := n.client.CustomGetDevices(n.options.NetboxOptions, n.options.NetboxDeviceOptions)
	if err != nil {
		n.logger.Error(err)
		return
	}

	buf := bytes.NewBuffer(data)

	var res []NetboxDevice
	err = json.NewDecoder(buf).Decode(&res)
	if err != nil {
		n.logger.Error(err)
		return
	}

	l := len(res)
	if l == 0 {
		n.logger.Debug("Netbox has no devices")
	}

	devices := n.makeDevicesSinkMap(res)
	n.logger.Debug("Netbox found %d devices. Processing...", len(devices))

	n.processors.Process(n, &NetboxSinkObject{
		sinkMap: devices,
		Netbox:  n,
	})
}

func NewNetbox(options NetboxOptions, observability *common.Observability, processors *common.Processors) *Netbox {

	logger := observability.Logs()

	if utils.IsEmpty(options.URL) {
		logger.Debug("Netbox has no URL. Skipped")
		return nil
	}

	return &Netbox{
		client:        toolsVendors.NewNetbox(options.NetboxOptions),
		options:       options,
		logger:        logger,
		observability: observability,
		processors:    processors,
	}
}
