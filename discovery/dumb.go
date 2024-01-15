package discovery

import (
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
)

type DumbOptions struct {
	Enabled   bool
	LabelsMap common.LabelsMap
	Schedule  string
}

// Dumb is a discovery that sends test data to sinks
type Dumb struct {
	options       DumbOptions
	logger        sreCommon.Logger
	observability *common.Observability
	sinks         *common.Sinks
}

type DumbSinkObject struct {
	dumb *Dumb
}

func (d *DumbSinkObject) Map() common.SinkMap {
	return common.ConvertLabelsMapToSinkMap(d.dumb.options.LabelsMap)
}

func (d *DumbSinkObject) Options() interface{} {
	return d.dumb.options
}

func (d *Dumb) Discover() {
	d.sinks.Process(d, &DumbSinkObject{dumb: d})
}

func (d *Dumb) Name() string {
	return "Dumb"
}

func (d *Dumb) Source() string {
	return "dumb"
}

func NewDumb(options DumbOptions, obs *common.Observability, sinks *common.Sinks) *Dumb {
	if !options.Enabled {
		return nil
	}

	if options.LabelsMap == nil {
		options.LabelsMap = make(common.LabelsMap)
	}
	if len(options.LabelsMap) == 0 {
		sm := make(common.LabelsMap)

		sm["object1"] = common.Labels{
			"label1": "value1",
			"label2": "value2",
		}

		sm["object2"] = common.Labels{
			"label1": "value1",
			"label2": "value2",
		}

		options.LabelsMap = sm
	}

	logger := obs.Logs()

	return &Dumb{
		options:       options,
		sinks:         sinks,
		logger:        logger,
		observability: obs,
	}
}
