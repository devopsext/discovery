package sink

import (
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
)

type YamlOptions struct {
	Dir       string
	Providers []string
}

type Yaml struct {
	options       YamlOptions
	logger        sreCommon.Logger
	observability *common.Observability
}

func (y *Yaml) Name() string {
	return "Yaml"
}

func (y *Yaml) Providers() []string {
	return y.options.Providers
}

func (y *Yaml) Process(d common.Discovery, so common.SinkObject) {

	m := so.Map()
	y.logger.Debug("Yaml has to process %d objects from %s...", len(m), d.Name())
	data, err := yaml.Marshal(m)
	if err != nil {
		y.logger.Error("Yaml Sink: %v", err)
		return
	}
	f, err := os.Create(filepath.Join(y.options.Dir, d.Name()+".yaml"))
	if err != nil {
		y.logger.Error("Yaml Sink: %v", err)
		return
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			y.logger.Error("Yaml Sink: %v", err)
		}
	}(f)
	_, err = f.Write(data)
	if err != nil {
		y.logger.Error("Yaml Sink: %v", err)
	}
}

func NewYaml(options YamlOptions, observability *common.Observability) *Yaml {

	logger := observability.Logs()

	if utils.IsEmpty(options.Dir) {
		logger.Debug("Yaml has no directory. Skipped")
		return nil
	}

	options.Providers = common.RemoveEmptyStrings(options.Providers)

	return &Yaml{
		options:       options,
		logger:        logger,
		observability: observability,
	}
}
