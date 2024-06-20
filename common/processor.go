package common

import (
	"reflect"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type Processor interface {
	Process(d Discovery, so SinkObject)
	Name() string
	Providers() []string
}

type Processors struct {
	list   []Processor
	sinks  *Sinks
	logger sreCommon.Logger
}

func (ps *Processors) Add(p Processor) {
	ps.list = append(ps.list, p)
}

func (ps *Processors) Process(d Discovery, so SinkObject) {

	for _, p := range ps.list {

		if reflect.ValueOf(p).IsNil() {
			continue
		}

		providers := p.Providers()
		if !utils.IsEmpty(providers) && !utils.Contains(providers, d.Name()) {
			ps.logger.Debug("%s has no %s in pass %s. Skipped", p.Name(), d.Name(), providers)
			continue
		}
		p.Process(d, so)
	}
	ps.sinks.Process(d, so)
}

func NewProcessors(observability *Observability, sinks *Sinks) *Processors {

	logger := observability.Logs()

	return &Processors{
		logger: logger,
		sinks:  sinks,
	}
}
