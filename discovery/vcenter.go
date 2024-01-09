package discovery

import (
	"encoding/json"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"github.com/jinzhu/copier"
)

type VCenterVMGuestIdentityFullName struct {
	OS string `json:"default_message"`
}

type VCenterVMGuestIdentity struct {
	FullName *VCenterVMGuestIdentityFullName `json:"full_name"`
	IP       string                          `json:"ip_address"`
	Host     string                          `json:"host_name"`
	Family   string                          `json:"family"`
}

type VCenterVMGuestIdentityResponse struct {
	Value *VCenterVMGuestIdentity `json:"value"`
}

type VCenterVM struct {
	VM       string `json:"vm"`
	Name     string `json:"name"`
	identity *VCenterVMGuestIdentity
}

type VCenterVMResponse struct {
	Value []*VCenterVM `json:"value"`
}

type VCenterHost struct {
	Host string `json:"host"`
	Name string `json:"name"`
	vms  []*VCenterVM
}

type VCenterHostResponse struct {
	Value []*VCenterHost `json:"value"`
}

type VCenterCluster struct {
	Cluster string `json:"cluster"`
	Name    string `json:"name"`
	hosts   []*VCenterHost
}

type VCenterClusterResponse struct {
	Value []*VCenterCluster `json:"value"`
}

type VCenterOptions struct {
	toolsVendors.VCenterOptions
	Schedule string
}

type VCenter struct {
	client        *toolsVendors.VCenter
	options       VCenterOptions
	logger        sreCommon.Logger
	observability *common.Observability
	sinks         *common.Sinks
}

type VCenterSinkObject struct {
	sinkMap common.SinkMap
	VCenter *VCenter
}

func (os *VCenterSinkObject) Map() common.SinkMap {
	return os.sinkMap
}

func (os *VCenterSinkObject) Slice() []interface{} {
	return common.ConvertLabelMapToSlice(common.ConvertSyncMapToLabelsMap(os.sinkMap))
}

func (os *VCenterSinkObject) Options() interface{} {
	return os.VCenter.options
}

func (vc *VCenter) Name() string {
	return "VCenter"
}

func (vc *VCenter) Source() string {
	return ""
}

func (vc *VCenter) getClusters(opts toolsVendors.VCenterOptions) ([]*VCenterCluster, error) {

	var r []*VCenterCluster

	data, err := vc.client.CustomGetClusters(opts)
	if err != nil {
		return r, err
	}

	var res VCenterClusterResponse
	if err := json.Unmarshal(data, &res); err != nil {
		return r, err
	}
	return res.Value, nil
}

func (vc *VCenter) getHosts(opts toolsVendors.VCenterOptions, cluster string) ([]*VCenterHost, error) {

	var r []*VCenterHost

	data, err := vc.client.CustomGetHosts(opts, toolsVendors.VCenterHostOptions{
		Cluster: cluster,
	})
	if err != nil {
		return r, err
	}

	var res VCenterHostResponse
	if err := json.Unmarshal(data, &res); err != nil {
		return r, err
	}
	return res.Value, nil
}

func (vc *VCenter) getVMs(opts toolsVendors.VCenterOptions, cluster, host string) ([]*VCenterVM, error) {

	var r []*VCenterVM

	data, err := vc.client.CustomGetVMs(opts, toolsVendors.VCenterVMOptions{
		Cluster: cluster,
		Host:    host,
	})
	if err != nil {
		return r, err
	}

	var res VCenterVMResponse
	if err := json.Unmarshal(data, &res); err != nil {
		return r, err
	}
	return res.Value, nil
}

func (vc *VCenter) getVMGuestidentity(opts toolsVendors.VCenterOptions, vm string) (*VCenterVMGuestIdentity, error) {

	data, err := vc.client.CustomGetVMGuestIdentity(opts, toolsVendors.VCenterVMGuestIdentityOptions{
		VM: vm,
	})
	if err != nil {
		return nil, err
	}

	var res VCenterVMGuestIdentityResponse
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return res.Value, nil
}

func (vc *VCenter) makeSinkMap(clusters []*VCenterCluster) common.SinkMap {

	r := make(common.SinkMap)

	for _, c := range clusters {

		for _, h := range c.hosts {

			for _, v := range h.vms {

				ip := ""
				host := v.Name
				os := ""
				if v.identity != nil {
					ip = common.IfDef(v.identity.IP, "").(string)
					host = common.IfDef(v.identity.Host, "").(string)
					os = common.IfDef(v.identity.FullName.OS, "").(string)
				}

				common.AppendHostSink(r, v.Name, common.HostSink{
					IP:      ip,
					Host:    host,
					OS:      os,
					Vendor:  "vSphere",
					Cluster: c.Name,
					Server:  h.Name,
				})
			}
		}
	}
	return r
}

func (vc *VCenter) setVMs(opts toolsVendors.VCenterOptions, host, name string, vms []*VCenterVM) {

	for _, v := range vms {

		identity, err := vc.getVMGuestidentity(opts, v.VM)
		if err != nil {
			vc.logger.Error("VCenter vm %s guest identity error: %s", v.Name, err)
			continue
		}
		v.identity = identity
	}
}

func (vc *VCenter) setHosts(opts toolsVendors.VCenterOptions, cluster, name string, hosts []*VCenterHost) {

	for _, h := range hosts {

		vms, err := vc.getVMs(opts, cluster, h.Host)
		if err != nil {
			vc.logger.Error("VCenter host %s vms error: %s", h.Name, err)
			continue
		}
		h.vms = vms

		if len(vms) == 0 {
			vc.logger.Debug("VCenter cluster %s host %s has no vms", name, h.Name)
			continue
		}
		vc.logger.Debug("VCenter cluster %s host %s found %d vms. Processing...", name, h.Name, len(vms))
		vc.setVMs(opts, h.Host, h.Name, vms)
	}
}

func (vc *VCenter) setClusters(opts toolsVendors.VCenterOptions, clusters []*VCenterCluster) {

	for _, c := range clusters {

		hosts, err := vc.getHosts(opts, c.Cluster)
		if err != nil {
			vc.logger.Error("VCenter cluster %s hosts error: %s", c.Name, err)
			continue
		}
		c.hosts = hosts

		if len(hosts) == 0 {
			vc.logger.Debug("VCenter cluster %s has no hosts", c.Name)
			continue
		}
		vc.logger.Debug("VCenter cluster %s found %d hosts. Processing...", c.Name, len(hosts))
		vc.setHosts(opts, c.Cluster, c.Name, hosts)
	}
}

func (vc *VCenter) Discover() {

	vc.logger.Debug("VCenter discovery by URL: %s", vc.options.URL)

	session, err := vc.client.CustomGetSession(vc.options.VCenterOptions)
	if err != nil {
		vc.logger.Error(err)
		return
	}

	// switch to session
	opts := toolsVendors.VCenterOptions{}
	copier.CopyWithOption(&opts, &vc.options.VCenterOptions, copier.Option{IgnoreEmpty: true, DeepCopy: true})
	opts.Password = ""
	opts.User = ""
	opts.Session = session

	clusters, err := vc.getClusters(opts)
	if err != nil {
		vc.logger.Error(err)
		return
	}

	if len(clusters) == 0 {
		vc.logger.Debug("VCenter has no clusters")
		return
	}
	vc.logger.Debug("VCenter found %d clusters. Processing...", len(clusters))
	vc.setClusters(opts, clusters)

	m := vc.makeSinkMap(clusters)
	vc.logger.Debug("VCenter found %d entries. Processing...", len(m))

	vc.sinks.Process(vc, &VCenterSinkObject{
		sinkMap: m,
		VCenter: vc,
	})
}

func NewVCenter(options VCenterOptions, observability *common.Observability, sinks *common.Sinks) *VCenter {

	logger := observability.Logs()

	if utils.IsEmpty(options.URL) {
		logger.Debug("VCenter has no URL. Skipped")
		return nil
	}

	return &VCenter{
		client:        toolsVendors.NewVCenter(options.VCenterOptions),
		options:       options,
		logger:        logger,
		observability: observability,
		sinks:         sinks,
	}
}
