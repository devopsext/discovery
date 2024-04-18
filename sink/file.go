package sink

import (
	"strings"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type FileOptions struct {
	Checksum     bool
	Providers    []string
	Names        []string
	Replacements string
}

type File struct {
	options       FileOptions
	logger        sreCommon.Logger
	observability *common.Observability
	replacements  map[string]string
}

func (f *File) Name() string {
	return "File"
}

func (f *File) Providers() []string {
	return f.options.Providers
}

func (f *File) replace(s string) string {

	r := s
	for k, v := range f.replacements {
		r = strings.Replace(r, k, v, 1)
	}
	return r
}

func (f *File) processPubSubPayloadFile(pf *discovery.PubSubMessagePayloadFile) {

	path := f.replace(pf.Path)
	exists, err := common.FileWriteWithCheckSum(path, pf.Data, f.options.Checksum)
	if err != nil {
		f.logger.Error("File couldn't be written to %s error: %s", path, err)
		return
	}

	if exists {
		f.logger.Debug("File exists in %s", path)
		return
	}
	f.logger.Debug("File created/updated in %s", path)
}

func (f *File) processPubSub(sm common.SinkMap) {

	for k, v := range sm {

		f.logger.Debug("File is processing payload %s...", k)
		pf, ok := v.(*discovery.PubSubMessagePayloadFile)
		if ok {
			f.processPubSubPayloadFile(pf)
		}
	}
}

func (f *File) Process(d common.Discovery, so common.SinkObject) {

	dname := d.Name()
	m := so.Map()
	f.logger.Debug("File has to process %d objects from %s...", len(m), d.Name())

	switch dname {
	case "PubSub":
		f.processPubSub(m)
	default:
		f.logger.Debug("File has no support for %s", dname)
		return
	}
}

func NewFile(options FileOptions, observability *common.Observability) *File {

	logger := observability.Logs()
	options.Providers = common.RemoveEmptyStrings(options.Providers)
	replacements := utils.MapGetKeyValues(options.Replacements)

	return &File{
		options:       options,
		logger:        logger,
		observability: observability,
		replacements:  replacements,
	}
}
