package sink

import (
	"fmt"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
)

type ObservabilityOptions struct {
	Pass []string
}

type Observability struct {
	options       ObservabilityOptions
	logger        sreCommon.Logger
	meter         sreCommon.Meter
	requests      sreCommon.Gauge
	observability *common.Observability
}

func (o *Observability) Name() string {
	return "Observability"
}

func (o *Observability) Pass() []string {
	return o.options.Pass
}

func (o *Observability) Process(d common.Discovery, so common.SinkObject) {

	dname := d.Name()
	m := so.Map()

	o.logger.Debug("Observability has to process %d objects from %s...", len(m), dname)

	lm := common.ConvertSyncMapToLabelsMap(m)
	if len(lm) == 0 {
		o.logger.Debug("Observability has no support for %s", dname)
		return
	}

	for k, _ := range lm {

		desc := fmt.Sprintf("Discovery from %s", dname)
		g := o.meter.Gauge("discovery", desc, []string{"name", "type"})
		g.Set(1, k, dname)
	}
}

func NewObservability(options ObservabilityOptions, observability *common.Observability) *Observability {

	logger := observability.Logs()
	meter := observability.Metrics()

	options.Pass = common.RemoveEmptyStrings(options.Pass)

	return &Observability{
		options:       options,
		logger:        logger,
		meter:         meter,
		observability: observability,
	}
}
