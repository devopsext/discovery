package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"gopkg.in/yaml.v3"
)

type SignalOptions struct {
	URL          string
	User         string
	Password     string
	Disabled     []string
	Schedule     string
	Query        string
	QueryPeriod  string
	QueryStep    string
	Metric       string
	Service      string
	Field        string
	BaseTemplate string
	Vars         string
	Files        string
}

type Signal struct {
	source          string
	prometheus      *toolsVendors.Prometheus
	prometheusOpts  toolsVendors.PrometheusOptions
	options         SignalOptions
	logger          sreCommon.Logger
	observability   *common.Observability
	serviceTemplate *toolsRender.TextTemplate
	fieldTemplate   *toolsRender.TextTemplate
	varsTemplate    *toolsRender.TextTemplate
	files           map[string]interface{}
	disables        map[string]*toolsRender.TextTemplate
	sinks           *common.Sinks
}

type SignalSinkObject struct {
	sinkMap common.SinkMap
	signal  *Signal
}

func (ss *SignalSinkObject) Map() common.SinkMap {
	return ss.sinkMap
}

func (ss *SignalSinkObject) Options() interface{} {
	return ss.signal.options
}

func (s *Signal) Name() string {
	return "Signal"
}

func (s *Signal) Source() string {
	return s.source
}

func (s *Signal) render(tpl *toolsRender.TextTemplate, def string, obj interface{}) string {

	s1, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		s.logger.Error(err)
		return def
	}
	return s1
}

// ".templates/SRE/service-*.yml"
func (s *Signal) readBaseConfigs() map[string]*common.BaseConfig {

	configs := make(map[string]*common.BaseConfig)

	files, err := filepath.Glob(s.options.BaseTemplate)
	if err != nil {
		s.logger.Error(err)
		return configs
	}

	if len(files) == 0 {
		s.logger.Error("%s: No base templates by pattern: %s", s.source, s.options.BaseTemplate)
		return configs
	}

	for _, v := range files {

		s.logger.Debug("%s: Processing base config: %s...", s.source, v)
		content, err := os.ReadFile(v)
		if err != nil {
			s.logger.Error(err)
			continue
		}

		config := &common.BaseConfig{}
		err = yaml.Unmarshal(content, config)
		if err != nil {
			s.logger.Error(err)
			continue
		}
		if config.Disabled {
			s.logger.Debug("%s: Base config is disabled: %s", s.source, v)
			continue
		}
		configs[v] = config
		s.logger.Debug("%s: Base config is loaded: %s", s.source, v)
	}
	return configs
}

func (s *Signal) readJson(bytes []byte) (interface{}, error) {

	var v interface{}
	err := json.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Signal) readToml(bytes []byte) (interface{}, error) {

	var v interface{}
	err := toml.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Signal) readYaml(bytes []byte) (interface{}, error) {

	var v interface{}
	err := yaml.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (s *Signal) readFile(path, typ string) interface{} {

	if _, err := os.Stat(path); err != nil {
		s.logger.Error(err)
		return nil
	}

	bytes, err := os.ReadFile(path)
	if err != nil {
		s.logger.Error(err)
		return nil
	}

	tp := strings.Replace(filepath.Ext(path), ".", "", 1)
	if typ != "" {
		tp = typ
	}

	var obj interface{}
	switch {
	case tp == "json":
		obj, err = s.readJson(bytes)
	case tp == "toml":
		obj, err = s.readToml(bytes)
	case (tp == "yaml") || (tp == "yml"):
		obj, err = s.readYaml(bytes)
	default:
		obj, err = s.readJson(bytes)
	}
	if err != nil {
		s.logger.Error(err)
		return nil
	}
	return obj
}

func (s *Signal) getFiles(vars map[string]string) map[string]*common.File {

	files := make(map[string]*common.File)

	tpl, err := toolsRender.NewTextTemplate(toolsRender.TemplateOptions{Content: s.options.Files}, s.observability)
	if err != nil {
		s.logger.Error(err)
		return files
	}

	fs := s.render(tpl, s.options.Files, vars)
	kv := utils.MapGetKeyValues(fs)
	for k, v := range kv {
		if utils.FileExists(v) {
			typ := strings.Replace(filepath.Ext(v), ".", "", 1)

			obj := s.files[v]
			if obj == nil {
				obj = s.readFile(v, typ)
			}

			if obj != nil {
				files[k] = &common.File{
					Path: v,
					Type: typ,
					Obj:  obj,
				}
				s.files[v] = obj
			}
		}
	}
	return files
}

func (s *Signal) expandDisabled(files map[string]*common.File, vars map[string]string) []string {

	r := []string{}
	m := make(map[string]interface{})

	fls := make(map[string]interface{})
	for k, v := range files {
		fls[k] = v.Obj
	}
	m["files"] = fls
	m["vars"] = vars

	for _, v := range s.options.Disabled {

		if !utils.FileExists(v) {
			if !utils.IsEmpty(v) && !utils.Contains(r, v) {
				r = append(r, v)
			}
			continue
		}

		tpl := s.disables[v]
		if tpl == nil {
			bytes, err := utils.Content(v)
			if err != nil {
				s.logger.Error(err)
				continue
			}
			t, err := toolsRender.NewTextTemplate(toolsRender.TemplateOptions{Content: string(bytes)}, s.observability)
			if err != nil {
				s.logger.Error(err)
				continue
			}
			tpl = t
			s.disables[v] = t
		}

		arr := []string{}
		sarr := s.render(tpl, "", m)
		if !utils.IsEmpty(sarr) {
			arr = strings.Split(sarr, ",")
		}
		for _, a := range arr {
			if !utils.IsEmpty(a) && !utils.Contains(r, a) {
				r = append(r, a)
			}
		}
	}
	return r
}

func (s *Signal) checkDisabled(disabled []string, service string) (bool, string) {

	for _, v := range disabled {

		match, _ := regexp.MatchString(v, service)
		if match {
			return true, v
		}
	}
	return false, ""
}

func (s *Signal) filterVectors(name string, configs map[string]*common.BaseConfig, vectors []*common.PrometheusResponseDataVector) []*common.PrometheusResponseDataVector {

	var r []*common.PrometheusResponseDataVector
	for _, v := range vectors {
		found := false
		n := v.Labels[name]
		if !utils.IsEmpty(n) {
			exists := false
			for _, c := range configs {
				if c.Disabled {
					continue
				}
				exists = c.Contains(n)
				if exists {
					break
				}
			}
			found = exists
		}
		if found {
			r = append(r, v)
		}
	}
	return r
}

func (s *Signal) findServices(vectors []*common.PrometheusResponseDataVector) map[string]*common.Service {

	configs := s.readBaseConfigs()
	matched := make(map[string]*common.Service)
	gid := utils.GoRoutineID()

	if utils.IsEmpty(s.options.Metric) {
		s.logger.Debug("[%d] %s: metric name is empty", gid, s.source)
		return matched
	}
	name := s.options.Metric

	l := len(vectors)
	s.logger.Debug("[%d] %s: found %d series", gid, s.source, l)
	if len(vectors) == 0 {
		return matched
	}

	vectors = s.filterVectors(name, configs, vectors)
	s.logger.Debug("[%d] %s: %d series filtered to %d", gid, s.source, l, len(vectors))

	when := time.Now()
	max := len(vectors) / 100

	for i, v := range vectors {

		if max > 0 && i%max == 0 && i > 0 {
			s.logger.Debug("[%d] %s: %d out of %d [%s]", gid, s.source, i, len(vectors), time.Since(when))
		}

		if len(v.Labels) < 2 {
			s.logger.Debug("[%d] %s: No labels, min requirements (2): %v", gid, s.source, v.Labels)
			continue
		}

		fls := s.getFiles(v.Labels)
		m := make(map[string]interface{})
		for k, v := range v.Labels {
			m[k] = v
		}
		files := make(map[string]interface{})
		for k, v := range fls {
			files[k] = v.Obj
		}
		m["files"] = files
		m["source"] = s.source

		vars := s.render(s.varsTemplate, s.options.Vars, m)
		serviceVars := utils.MapGetKeyValues(vars)
		mergedVars := common.MergeStringMaps(v.Labels, serviceVars)

		service := ""
		field := ""

		if utils.IsEmpty(s.options.Service) && (len(v.Labels) > 1) {
			flag := false
			for _, m := range v.Labels {
				if flag {
					service = m
					break
				}
				flag = true
			}
		} else {
			ident := s.render(s.serviceTemplate, s.options.Service, mergedVars)
			if ident == s.options.Service {
				service = mergedVars[ident]
			} else {
				service = ident
			}
		}

		ident := s.render(s.fieldTemplate, s.options.Field, mergedVars)
		if ident == s.options.Field {
			field = mergedVars[ident]
		} else {
			field = ident
		}

		metric := mergedVars[name]

		if utils.IsEmpty(service) || utils.IsEmpty(metric) {
			s.logger.Debug("[%d] %s: No service, field or metric found in labels, but: %v", gid, s.source, mergedVars)
			continue
		}

		// find service in cmdb
		// if it's disabled, skip it with warning
		fieldAndService := fmt.Sprintf("%s/%s", field, service)

		disabled := s.expandDisabled(fls, mergedVars)
		dis, _ := s.checkDisabled(disabled, service)
		if dis {
			//s.logger.Trace("%s: %s disabled by pattern: %s", s.source, fieldAndService, pattern)
			continue
		}

		for path, config := range configs {

			if config.Disabled {
				continue
			}

			exists := config.MetricExists(metric, mergedVars)
			if !exists {
				continue
			}

			ds := matched[fieldAndService]
			if ds == nil {
				s.logger.Debug("[%d] %s: %s found by: %v [%s]", gid, s.source, fieldAndService, mergedVars, time.Since(when))
				ds = &common.Service{
					Configs: make(map[string]*common.BaseConfig),
					Vars:    make(map[string]string),
				}
			}

			if !utils.Contains(ds.Metrics, metric) {
				ds.Metrics = append(ds.Metrics, metric)
			}

			if ds.Configs[path] == nil {
				ds.Configs[path] = config
			}
			for k, l := range serviceVars {
				if (ds.Vars[k] == "") && (l != metric) {
					ds.Vars[k] = l
				}
			}
			ds.Files = fls
			matched[fieldAndService] = ds
		}
	}
	return matched
}

func (s *Signal) Discover() {

	s.logger.Debug("%s: Signal discovery by query: %s", s.source, s.options.Query)

	if !utils.IsEmpty(s.options.QueryPeriod) {
		// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
		t := time.Now().UTC()
		s.prometheusOpts.From = common.ParsePeriodFromNow(s.options.QueryPeriod, t)
		s.prometheusOpts.To = strconv.Itoa(int(t.Unix()))
		s.prometheusOpts.Step = s.options.QueryStep
		if utils.IsEmpty(s.prometheusOpts.Step) {
			s.prometheusOpts.Step = "15s"
		}
		s.logger.Debug("%s: Signal discovery range: %s <-> %s", s.source, s.prometheusOpts.From, s.prometheusOpts.To)
	}

	data, err := s.prometheus.CustomGet(s.prometheusOpts)
	if err != nil {
		s.logger.Error(err)
		return
	}

	var res common.PrometheusResponse
	if err := json.Unmarshal(data, &res); err != nil {
		s.logger.Error(err)
		return
	}

	if res.Status != "success" {
		s.logger.Error(res.Status)
		return
	}

	if (res.Data == nil) || (len(res.Data.Result) == 0) {
		s.logger.Error("%s: Signal empty data on response", s.source)
		return
	}

	if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
		s.logger.Error("%s: Signal only vector and matrix are allowed", s.source)
		return
	}

	services := s.findServices(res.Data.Result)
	if len(services) == 0 {
		s.logger.Debug("%s: Signal not found any services according query", s.source)
		return
	}
	s.logger.Debug("%s: Signal found %d services according query. Processing...", s.source, len(services))

	s.sinks.Process(s, &SignalSinkObject{
		sinkMap: common.ConvertServicesToSinkMap(services),
		signal:  s,
	})
}

func NewSignal(source string, prometheusOptions common.PrometheusOptions, options SignalOptions, observability *common.Observability, sinks *common.Sinks) *Signal {

	logger := observability.Logs()

	if utils.IsEmpty(prometheusOptions.URL) {
		logger.Debug("%s: Signal no prometheus URL. Skipped", source)
		return nil
	}

	if utils.IsEmpty(options.Query) {
		logger.Debug("%s: Signal no signal query. Skipped", source)
		return nil
	}

	// this is needed to build Telegraf config with URL
	if utils.IsEmpty(options.URL) {
		options.URL = prometheusOptions.URL
	}

	// this is needed to build Telegraf config with user & password
	if !utils.IsEmpty(prometheusOptions.User) && !utils.IsEmpty(prometheusOptions.Password) {
		options.User = prometheusOptions.User
		options.Password = prometheusOptions.Password
	}

	varsOpts := toolsRender.TemplateOptions{
		Content: options.Vars,
		Name:    "signal-vars",
	}
	varsTemplate, err := toolsRender.NewTextTemplate(varsOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	serviceOpts := toolsRender.TemplateOptions{
		Content: options.Service,
		Name:    "signal-service",
	}
	serviceTemplate, err := toolsRender.NewTextTemplate(serviceOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	fieldOpts := toolsRender.TemplateOptions{
		Content: options.Field,
		Name:    "signal-field",
	}
	fieldTemplate, err := toolsRender.NewTextTemplate(fieldOpts, observability)
	if err != nil {
		logger.Error(err)
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

	return &Signal{
		source:          source,
		prometheus:      toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts:  prometheusOpts,
		options:         options,
		logger:          logger,
		observability:   observability,
		serviceTemplate: serviceTemplate,
		fieldTemplate:   fieldTemplate,
		varsTemplate:    varsTemplate,
		files:           make(map[string]interface{}),
		disables:        make(map[string]*toolsRender.TextTemplate),
		sinks:           sinks,
	}
}
