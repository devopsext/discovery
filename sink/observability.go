package sink

import (
	"fmt"
	"strings"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type ObservabilityOptions struct {
	DiscoveryName string
	TotalName     string
	Providers     []string
	Labels        []string
}

type Observability struct {
	options       ObservabilityOptions
	logger        sreCommon.Logger
	meter         sreCommon.Meter
	observability *common.Observability
}

func (o *Observability) Name() string {
	return "Observability"
}

func (o *Observability) Providers() []string {
	return o.options.Providers
}

func (o *Observability) getDiscoveryName() string {

	if !utils.IsEmpty(o.options.DiscoveryName) {
		return o.options.DiscoveryName
	}
	return strings.ToLower(o.Name())
}

func (o *Observability) getTotalName() string {

	if !utils.IsEmpty(o.options.TotalName) {
		return o.options.TotalName
	}
	return strings.ToLower(fmt.Sprintf("%s_total", o.Name()))
}

func (o *Observability) Process(d common.Discovery, so common.SinkObject) {

	dname := d.Name()
	m := so.Map()

	o.logger.Debug("Observability has to process %d objects from %s...", len(m), dname)

	var lm common.LabelsMap

	switch dname {
	case "Signal":
		ms := common.ConvertSyncMapToServices(m)
		if len(ms) == 0 {
			break
		}
		lm = make(map[string]common.Labels)
		for k1, s1 := range ms {
			lm[k1] = s1.Vars
		}
	default:
		lm = common.ConvertSyncMapToLabelsMap(m)
	}

	if len(lm) == 0 {
		o.logger.Debug("Observability has no support for %s", dname)
		return
	}

	labels := make(sreCommon.Labels)
	labels["provider"] = dname
	c := o.meter.Counter(o.getTotalName(), "Discovered total", labels)

	dn := o.getDiscoveryName()

	for k, v := range lm {

		labels := make(sreCommon.Labels)
		labels["name"] = k
		labels["provider"] = dname
		labels = common.MergeStringMaps(labels, common.FilterStringMap(v, o.options.Labels))
		g := o.meter.Gauge(dn, "Discovery existence", labels)
		g.Set(1)
	}
	c.Add(len(lm))

}

func NewObservability(options ObservabilityOptions, observability *common.Observability) *Observability {

	logger := observability.Logs()
	meter := observability.Metrics()

	options.Providers = common.RemoveEmptyStrings(options.Providers)
	options.Labels = common.RemoveEmptyStrings(options.Labels)

	return &Observability{
		options:       options,
		logger:        logger,
		meter:         meter,
		observability: observability,
	}
}
