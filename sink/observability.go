package sink

import (
	"fmt"
	"os"
	"strings"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
)

type ObservabilityOptions struct {
	DiscoveryName string
	TotalName     string
	Providers     []string
	Labels        []string
}

type Observability struct {
	options       ObservabilityOptions
	logger        sreCommon.Logger
	meter         sreCommon.Meter
	observability *common.Observability
}

func (o *Observability) Name() string {
	return "Observability"
}

func (o *Observability) Providers() []string {
	return o.options.Providers
}

func (o *Observability) getDiscoveryName() string {

	if !utils.IsEmpty(o.options.DiscoveryName) {
		return o.options.DiscoveryName
	}
	return strings.ToLower(o.Name())
}

func (o *Observability) getTotalName() string {

	if !utils.IsEmpty(o.options.TotalName) {
		return o.options.TotalName
	}
	return strings.ToLower(fmt.Sprintf("%s_total", o.Name()))
}

func (o *Observability) Process(d common.Discovery, so common.SinkObject) {

	dname := d.Name()
	dsource := d.Source()
	m := so.Map()

	o.logger.Debug("Observability has to process %d objects from %s source %s...", len(m), dname, dsource)

	var lm common.LabelsMap

	group := dname
	if !utils.IsEmpty(dsource) {
		group = fmt.Sprintf("%s/%s", dname, dsource)
	}
	o.meter.Group(group).Clear()

	switch dname {
	case "Signal":

		ms := common.ConvertSinkMapToObjects(m)
		if len(ms) == 0 {
			break
		}
		lm = make(map[string]common.Labels)
		for k1, s1 := range ms {
			lm[k1] = s1.Vars
		}

	case "PubSub":

		lm = make(map[string]common.Labels)
		for k, v := range m {
			pf, ok := v.(*discovery.PubSubMessagePayloadFile)
			if !ok {
				continue
			}
			lml := make(common.Labels)
			lml["path"] = pf.Path
			lml["kind"] = "file"
			lml["size"] = fmt.Sprintf("%d", len(pf.Data))
			lm[k] = lml
		}

	case "Files":

		lm = make(map[string]common.Labels)
		for k, v := range m {
			pf, ok := v.(string)
			if !ok {
				continue
			}
			lml := make(common.Labels)
			lml["path"] = pf

			fi, err := os.Stat(pf)
			if err == nil {
				lml["size"] = fmt.Sprintf("%d", fi.Size())
			}

			if err != nil {
				lml["error"] = err.Error()
			}
			lm[k] = lml
		}

	case "K8s":

		lm = make(map[string]common.Labels)
		for k, v := range m {
			ks, ok := v.(common.SinkMap)
			if ok {
				for s, i := range ks {
					lm[s] = common.MergeLabels(i.(common.Labels), common.Labels{"kind": k})
				}
			}
		}

	default:
		lm = common.ConvertSinkMapToLabelsMap(m)
	}

	if len(lm) == 0 {
		o.logger.Debug("Observability has no support for %s source %s", dname, dsource)
		return
	}

	labels := make(sreCommon.Labels)
	labels["provider"] = dname
	if !utils.IsEmpty(dsource) {
		labels["source"] = dsource
	}

	c := o.meter.Counter(group, o.getTotalName(), "Discovered total", labels)

	dn := o.getDiscoveryName()

	wrongKeys := make(map[string]string)
	wrongKeys["/"] = "_"
	wrongKeys["."] = "_"
	wrongKeys["-"] = "_"

	wrongValues := make(map[string]string)
	wrongValues["\""] = ""

	instLabel := "instance"

	for k, v := range lm {
		labels := make(sreCommon.Labels)
		labels["name"] = k
		labels["provider"] = dname
		labels = common.MergeStringMaps(labels, common.FilterStringMap(v, o.options.Labels))
		labels = common.ReplaceLabelKeys(labels, wrongKeys)
		labels = common.ReplaceLabelValues(labels, wrongValues)
		if !utils.IsEmpty(v[instLabel]) {
			insts := strings.Split(v[instLabel], ",")
			for _, i := range insts {
				labels[instLabel] = i
				g := o.meter.Gauge(group, dn, "Discovery existence", labels)
				g.Set(1)
			}
			continue
		}
		g := o.meter.Gauge(group, dn, "Discovery existence", labels)
		g.Set(1)
	}
	c.Add(len(lm))
}

func NewObservability(options ObservabilityOptions, observability *common.Observability) *Observability {

	logger := observability.Logs()
	meter := observability.Metrics()

	options.Providers = common.RemoveEmptyStrings(options.Providers)
	options.Labels = common.RemoveEmptyStrings(options.Labels)

	return &Observability{
		options:       options,
		logger:        logger,
		meter:         meter,
		observability: observability,
	}
}
