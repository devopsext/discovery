package discovery

import (
	"encoding/json"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type TeleportResourceClusterMetadata struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
}

type TeleportResourceCluster struct {
	Kind     string                          `json:"kind"`
	Metadata TeleportResourceClusterMetadata `json:"metadata"`
}

type TeleportResourceSpec struct {
	Version string                  `json:"version"`
	Cluster TeleportResourceCluster `json:"cluster"`
}

type TeleportResource struct {
	Kind string               `json:"kind"`
	Spec TeleportResourceSpec `json:"spec"`
}

type TeleportOptions struct {
	toolsVendors.TeleportOptions
	Schedule string
	Kinds    []string
}

type Teleport struct {
	client        *toolsVendors.Teleport
	options       TeleportOptions
	logger        sreCommon.Logger
	observability *common.Observability
	processors    *common.Processors
}

type TeleportSinkObject struct {
	sinkMap  common.SinkMap
	teleport *Teleport
}

func (os *TeleportSinkObject) Map() common.SinkMap {
	return os.sinkMap
}

func (os *TeleportSinkObject) Options() interface{} {
	return os.teleport.options
}

func (t *Teleport) Name() string {
	return "Teleport"
}

func (t *Teleport) Source() string {
	return ""
}

func (t *Teleport) makeResourcesSinkMap(resources []TeleportResource) common.SinkMap {

	r := make(common.SinkMap)

	for _, m := range resources {
		common.AppendSinkLabels(r, m.Spec.Cluster.Metadata.Name, m.Spec.Cluster.Metadata.Labels)
	}
	return r
}

func (t *Teleport) Discover() {

	t.logger.Debug("Teleport discovery by address: %s", t.options.Address)

	resourcses := []TeleportResource{}

	for _, kind := range t.options.Kinds {

		opts := toolsVendors.TeleportResourceListOptions{
			TeleportResourceOptions: toolsVendors.TeleportResourceOptions{
				Kind: kind,
			},
		}

		t.logger.Debug("Teleport resource list for kind: %s...", kind)

		data, err := t.client.CustomResourceList(t.options.TeleportOptions, opts)
		if err != nil {
			t.logger.Error("Teleport resource list error: %v", err)
			continue
		}

		t.logger.Debug("Teleport resource list data: %s", string(data))

		var res []TeleportResource
		if err := json.Unmarshal(data, &res); err != nil {
			t.logger.Error("Teleport resource unmarshal error: %v", err)
			continue
		}
		resourcses = append(resourcses, res...)
	}

	if len(resourcses) == 0 {
		t.logger.Debug("Teleport has no resourcses")
	}

	m := t.makeResourcesSinkMap(resourcses)
	t.logger.Debug("Teleport found %d resources. Processing...", len(m))

	t.processors.Process(t, &TeleportSinkObject{
		sinkMap:  m,
		teleport: t,
	})
}

func NewTeleport(options TeleportOptions, observability *common.Observability, processors *common.Processors) *Teleport {

	logger := observability.Logs()

	if utils.IsEmpty(options.Address) {
		logger.Debug("Teleport has no address. Skipped")
		return nil
	}

	return &Teleport{
		client:        toolsVendors.NewTeleport(options.TeleportOptions, observability),
		options:       options,
		logger:        logger,
		observability: observability,
		processors:    processors,
	}
}
