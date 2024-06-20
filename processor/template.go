package processor

import (
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
)

type TemplateOptions struct {
	Providers []string
}

type Template struct {
	options       TemplateOptions
	logger        sreCommon.Logger
	observability *common.Observability
	sinks         *common.Sinks
}

func (t *Template) Name() string {
	return "Template"
}

func (t *Template) Providers() []string {
	return t.options.Providers
}

func (t *Template) Process(d common.Discovery, so common.SinkObject) {
	//
}

func NewTemplate(options TemplateOptions, observability *common.Observability, sinks *common.Sinks) *Template {

	logger := observability.Logs()
	options.Providers = common.RemoveEmptyStrings(options.Providers)

	return &Template{
		options:       options,
		logger:        logger,
		observability: observability,
		sinks:         sinks,
	}
}
