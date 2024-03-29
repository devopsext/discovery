package sink

import (
	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	sreCommon "github.com/devopsext/sre/common"
)

type FileOptions struct {
	Checksum  bool
	Providers []string
	Names     []string
}

type File struct {
	options       FileOptions
	logger        sreCommon.Logger
	observability *common.Observability
}

func (f *File) Name() string {
	return "Json"
}

func (f *File) Providers() []string {
	return f.options.Providers
}

func (f *File) processPubSubPayloadFile(pf *discovery.PubSubMessagePayloadFile) {

	exists, err := common.FileWriteWithCheckSum(pf.Path, pf.Data, f.options.Checksum)
	if err != nil {
		f.logger.Error("File couldn't be written to %s error: %s", pf.Path, err)
		return
	}

	if exists {
		f.logger.Debug("File exists in %s", pf.Path)
		return
	}
	f.logger.Debug("File created/updated in %s", pf.Path)
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

	return &File{
		options:       options,
		logger:        logger,
		observability: observability,
	}
}
