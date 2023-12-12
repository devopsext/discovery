package common

import (
	"reflect"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type SinkMap map[string]interface{}

type SinkObject interface {
	Map() SinkMap
	Options() interface{}
}

type Sink interface {
	Process(d Discovery, so SinkObject)
	Name() string
	Pass() []string
}

type Sinks struct {
	list   []Sink
	logger sreCommon.Logger
}

type HostSink struct {
	IP     string
	Host   string
	Vendor string
}

func AppendHostSink(m SinkMap, name string, hs HostSink) {

	if m == nil || utils.IsEmpty(name) {
		return
	}
	labels := make(Labels)
	labels["ip"] = hs.IP
	labels["host"] = hs.Host
	labels["vendor"] = hs.Vendor
	m[name] = labels
}

func (ss *Sinks) Add(s Sink) {
	ss.list = append(ss.list, s)
}

func (ss *Sinks) Process(d Discovery, so SinkObject) {

	for _, s := range ss.list {

		if reflect.ValueOf(s).IsNil() {
			continue
		}

		pass := s.Pass()
		if !utils.IsEmpty(pass) && !utils.Contains(pass, d.Name()) {
			ss.logger.Debug("%s has no %s in pass %s. Skipped", s.Name(), d.Name(), pass)
			continue
		}
		s.Process(d, so)
	}
}

func NewSinks(observability *Observability) *Sinks {

	logger := observability.Logs()

	return &Sinks{
		logger: logger,
	}
}
