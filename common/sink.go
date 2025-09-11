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
	Providers() []string
}

type Sinks struct {
	list   []Sink
	logger sreCommon.Logger
}

type HostSink struct {
	IP      string
	Host    string
	Vendor  string
	OS      string
	Cluster string
	Server  string
}

func AppendSinkLabels(m SinkMap, name string, lbs Labels) {

	if m == nil || utils.IsEmpty(name) {
		return
	}

	labels := make(Labels)
	for k, v := range lbs {
		labels[k] = v
	}
	m[name] = labels
}

func AppendHostSinkLabels(m SinkMap, name string, hs HostSink, lbs Labels) {

	if m == nil || utils.IsEmpty(name) {
		return
	}
	labels := make(Labels)
	if !utils.IsEmpty(hs.Host) {
		labels["host"] = hs.Host
	}

	if !utils.IsEmpty(hs.IP) {
		labels["ip"] = hs.IP
	}

	if !utils.IsEmpty(hs.Vendor) {
		labels["vendor"] = hs.Vendor
	}

	if !utils.IsEmpty(hs.OS) {
		labels["os"] = hs.OS
	}

	if !utils.IsEmpty(hs.Cluster) {
		labels["cluster"] = hs.Cluster
	}

	if !utils.IsEmpty(hs.Server) {
		labels["server"] = hs.Server
	}

	for k, v := range lbs {
		labels[k] = v
	}
	m[name] = labels
}

func AppendHostSink(m SinkMap, name string, hs HostSink) {

	AppendHostSinkLabels(m, name, hs, nil)
}

func (ss *Sinks) Add(s Sink) {
	if s != nil {
		ss.list = append(ss.list, s)
	}
}

func (ss *Sinks) Process(d Discovery, so SinkObject) {

	for _, s := range ss.list {

		if reflect.ValueOf(s).IsNil() {
			continue
		}

		providers := s.Providers()
		if !utils.IsEmpty(providers) && !utils.Contains(providers, d.Name()) {
			ss.logger.Debug("%s has no %s in pass %s. Skipped", s.Name(), d.Name(), providers)
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
