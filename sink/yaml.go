package sink

import (
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type YamlOptions struct {
	Dir string
}

type Yaml struct {
	options       YamlOptions
	logger        sreCommon.Logger
	observability *common.Observability
}

func (y *Yaml) Name() string {
	return "Yaml"
}

func (y *Yaml) Pass() []string {
	return []string{}
}

func (y *Yaml) Process(d common.Discovery, so common.SinkObject) {

	m := so.Map()
	y.logger.Debug("Yaml has to process %d objects from %s...", len(m), d.Name())

}

func NewYaml(options YamlOptions, observability *common.Observability) *Yaml {

	logger := observability.Logs()

	if utils.IsEmpty(options.Dir) {
		logger.Debug("Yaml has no directory. Skipped")
		return nil
	}

	return &Yaml{
		options:       options,
		logger:        logger,
		observability: observability,
	}
}
