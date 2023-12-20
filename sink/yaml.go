package sink

import (
	"encoding/json"
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"os"
	"path/filepath"
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

func (y *Yaml) Providers() []string {
	return []string{}
}

func (y *Yaml) Process(d common.Discovery, so common.SinkObject) {

	m := so.Map()
	y.logger.Debug("Yaml has to process %d objects from %s...", len(m), d.Name())
	data, err := json.Marshal(m)
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
