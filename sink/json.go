package sink

import (
	"encoding/json"
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"os"
	"path/filepath"
)

type JsonOptions struct {
	Dir       string
	Providers []string
}

type Json struct {
	options       JsonOptions
	logger        sreCommon.Logger
	observability *common.Observability
}

func (j *Json) Name() string {
	return "Json"
}

func (j *Json) Providers() []string {
	return j.options.Providers
}

func (j *Json) Process(d common.Discovery, so common.SinkObject) {

	m := so.Map()
	j.logger.Debug("Json has to process %d objects from %s...", len(m), d.Name())
	data, err := json.Marshal(m)
	if err != nil {
		j.logger.Error("Json Sink: %v", err)
		return
	}
	f, err := os.Create(filepath.Join(j.options.Dir, d.Name()+".json"))
	if err != nil {
		j.logger.Error("Json Sink: %v", err)
		return
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			j.logger.Error("Json Sink: %v", err)
		}
	}(f)
	_, err = f.Write(data)
	if err != nil {
		j.logger.Error("Json Sink: %v", err)
	}
}

func NewJson(options JsonOptions, observability *common.Observability) *Json {

	logger := observability.Logs()

	if utils.IsEmpty(options.Dir) {
		logger.Debug("Json has no directory. Skipped")
		return nil
	}

	options.Providers = common.RemoveEmptyStrings(options.Providers)

	return &Json{
		options:       options,
		logger:        logger,
		observability: observability,
	}
}
