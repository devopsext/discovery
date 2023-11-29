package sink

import (
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type JsonOptions struct {
	Dir string
}

type Json struct {
	options       JsonOptions
	logger        sreCommon.Logger
	observability *common.Observability
}

func (j *Json) Name() string {
	return "Json"
}

func (j *Json) Pass() []string {
	return []string{}
}

func (j *Json) Process(d common.Discovery, so common.SinkObject) {

	m := so.Map()
	j.logger.Debug("Json has to process %d objects from %s...", len(m), d.Name())
}

func NewJson(options JsonOptions, observability *common.Observability) *Json {

	logger := observability.Logs()

	if utils.IsEmpty(options.Dir) {
		logger.Debug("Json has no directory. Skipped")
		return nil
	}

	return &Json{
		options:       options,
		logger:        logger,
		observability: observability,
	}
}
