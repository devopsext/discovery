package discovery

import (
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
)

type PrometheusOptions struct {
	Query       string
	QueryKeys   string
	QueryPeriod string
	QueryStep   string
	Schedule    string
	Source      string
}

type Prometheus struct {
	source         string
	prometheus     *toolsVendors.Prometheus
	prometheusOpts toolsVendors.PrometheusOptions
	options        PrometheusOptions
	logger         sreCommon.Logger
	observability  *common.Observability
	processors     *common.Processors
	queries        map[string]string
	keys           map[string]*toolsRender.TextTemplate
	lock           sync.Mutex
}

type PrometheusQuery struct {
	name       string
	prometheus *Prometheus
}

type PrometheusQuerySinkObject struct {
	sinkMap common.SinkMap
	query   *PrometheusQuery
}

const prometheusName = "Prometheus"

// Prometheus query
func (pq *PrometheusQuery) Name() string {
	return pq.name
}

func (pq *PrometheusQuery) Source() string {
	return pq.prometheus.source
}

func (pq *PrometheusQuery) Discover() {
	// no-op
}

// PrometheusQuerySinkObject
func (ps *PrometheusQuerySinkObject) Map() common.SinkMap {
	return ps.sinkMap
}

func (ps *PrometheusQuerySinkObject) Options() interface{} {
	return nil
}

// Prometheus
func (p *Prometheus) Name() string {
	return prometheusName
}

func (p *Prometheus) Source() string {
	return p.source
}

func (p *Prometheus) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		p.logger.Error(err)
		return def
	}
	return s1
}

func (p *Prometheus) transform(gid uint64, name string, vectors []*common.PrometheusResponseDataVector) common.LabelsMap {

	ret := make(common.LabelsMap)

	l1 := len(vectors)
	p.logger.Debug("[%d] %s: Prometheus found %d series on query %s", gid, p.source, l1, name)
	if len(vectors) == 0 {
		return ret
	}

	tpl, ok := p.keys[name]
	if !ok {
		p.logger.Error("[%d] %s: Prometheus has not found name template on query %s", gid, p.source, name)
		return ret
	}

	for _, v := range vectors {

		if len(v.Labels) < 1 {
			p.logger.Debug("[%d] %s: Prometheus has not found data, min requirements (1) for query %s: %v", gid, p.source, name, v.Labels)
			continue
		}

		key := p.render(tpl, name, v.Labels)
		if utils.IsEmpty(key) {
			p.logger.Debug("[%d] %s: Prometheus has no key found in labels for query %s, but: %v", gid, p.source, name, v.Labels)
			continue
		}
		ret[key] = v.Labels
	}
	return ret
}

func (p *Prometheus) discoveryByQuery(name string, promOpts toolsVendors.PrometheusOptions) {

	gid := utils.GoRoutineID()

	p.logger.Debug("[%d] %s: Prometheus discovery by query %s: %s", gid, p.source, name, promOpts.Query)
	p.logger.Debug("[%d] %s: Prometheus discovery range %s: %s <-> %s", gid, p.source, name, promOpts.From, promOpts.To)

	data, err := p.prometheus.CustomGet(promOpts)
	if err != nil {
		p.logger.Error("[%d] %s: Prometheus query %s failed: %v", gid, p.source, name, err)
		return
	}

	var res common.PrometheusResponse
	if err := json.Unmarshal(data, &res); err != nil {
		p.logger.Error(err)
		return
	}

	if res.Status != "success" {
		p.logger.Error(res.Status)
		return
	}

	if (res.Data == nil) || (len(res.Data.Result) == 0) {
		p.logger.Error("[%d] %s: Prometheus empty data on query %s response", gid, p.source, name)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		p.logger.Error("[%d] %s: Prometheus only vector and matrix are allowed on query %s", gid, p.source, name)
		return
	}

	tdata := p.transform(gid, name, res.Data.Result)
	if len(tdata) == 0 {
		p.logger.Debug("[%d] %s: Prometheus not found any data according query %s", gid, p.source, name)
		return
	}
	p.logger.Debug("[%d] %s: Prometheus found %d data according query %s. Processing...", gid, p.source, len(tdata), name)

	pq := &PrometheusQuery{
		name:       name,
		prometheus: p,
	}

	p.processors.Process(pq, &PrometheusQuerySinkObject{
		sinkMap: common.ConvertLabelsMapToSinkMap(tdata),
		query:   pq,
	})
}

func (p *Prometheus) Discover() {

	if !p.lock.TryLock() {
		return
	}
	defer p.lock.Unlock()

	for name, query := range p.queries {

		promOpts := toolsVendors.PrometheusOptions{
			URL:      p.prometheusOpts.URL,
			User:     p.prometheusOpts.User,
			Password: p.prometheusOpts.Password,
			Timeout:  p.prometheusOpts.Timeout,
			Insecure: p.prometheusOpts.Insecure,
			Query:    query,
			Step:     p.prometheusOpts.Step,
		}

		if !utils.IsEmpty(p.options.QueryPeriod) {
			// https://Signap.io/docs/Signal/latest/querying/api/#range-queries
			t := time.Now().UTC()
			promOpts.From = common.ParsePeriodFromNow(p.options.QueryPeriod, t)
			promOpts.To = strconv.Itoa(int(t.Unix()))
			if utils.IsEmpty(promOpts.Step) {
				promOpts.Step = "15s"
			}
		}

		go p.discoveryByQuery(name, promOpts)
	}
}

func NewPrometheus(source string, prometheusOptions common.PrometheusOptions, options PrometheusOptions, observability *common.Observability, processors *common.Processors) *Prometheus {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: Prometheus has no URL. Skipped", source)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: Prometheus has no query. Skipped", source)
		return nil
	}

	if utils.IsEmpty(options.QueryKeys) {
		logger.Debug("%s: Prometheus has no query keys. Skipped", source)
		return nil
	}

	prometheusOpts := toolsVendors.PrometheusOptions{
		URL:      prometheusOptions.URL,
		User:     prometheusOptions.User,
		Password: prometheusOptions.Password,
		Timeout:  prometheusOptions.Timeout,
		Insecure: prometheusOptions.Insecure,
		Query:    options.Query,
	}

	// find out queries
	queries := make(map[string]string)
	m := utils.MapGetKeyValues(options.Query)

	for k, v := range m {

		q := v
		if utils.FileExists(q) {
			q1, err := utils.Content(q)
			if err == nil {
				q = string(q1)
			}
		}
		if !utils.IsEmpty(q) {
			queries[k] = q
		}
	}

	// set default query if not exists
	if len(queries) == 0 {
		q, err := utils.Content(options.Query)
		if err == nil && !utils.IsEmpty(q) {
			queries[prometheusName] = string(q)
		}
	}

	if len(queries) == 0 {
		logger.Debug("%s: Prometheus has no queries. Skipped", source)
		return nil
	}

	// find out names templates
	keys := make(map[string]*toolsRender.TextTemplate)
	mn := utils.MapGetKeyValues(options.QueryKeys)

	for k, v := range mn {

		nameOpts := toolsRender.TemplateOptions{
			Content:     v,
			Name:        fmt.Sprintf("query-name-%s", k),
			FilterFuncs: true,
		}
		tpl, err := toolsRender.NewTextTemplate(nameOpts, observability)
		if err != nil {
			logger.Error(err)
			return nil
		}
		keys[k] = tpl
	}

	// set default name template if not exists
	if len(keys) == 0 {

		nameOpts := toolsRender.TemplateOptions{
			Content:     options.QueryKeys,
			Name:        fmt.Sprintf("query-name-%s", prometheusName),
			FilterFuncs: true,
		}
		tpl, err := toolsRender.NewTextTemplate(nameOpts, observability)
		if err != nil {
			logger.Error(err)
			return nil
		}
		keys[prometheusName] = tpl
	}

	if len(keys) == 0 {
		logger.Debug("%s: Prometheus has no query keys. Skipped", source)
		return nil
	}

	return &Prometheus{
		source:         source,
		prometheus:     toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts: prometheusOpts,
		options:        options,
		logger:         logger,
		observability:  observability,
		processors:     processors,
		queries:        queries,
		keys:           keys,
	}
}
