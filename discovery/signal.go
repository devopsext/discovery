package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/allegro/bigcache"
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
	Ident        string
	Field        string
	BaseTemplate string
	Vars         string
	Files        string
	CacheSize    int
}

type SignalCache struct {
	logger   sreCommon.Logger
	cache    *bigcache.BigCache
	template *toolsRender.TextTemplate
}

type Signal struct {
	source         string
	prometheus     *toolsVendors.Prometheus
	prometheusOpts toolsVendors.PrometheusOptions
	options        SignalOptions
	logger         sreCommon.Logger
	observability  *common.Observability
	objectTemplate *toolsRender.TextTemplate
	fieldTemplate  *toolsRender.TextTemplate
	filesTemplate  *toolsRender.TextTemplate
	files          *sync.Map
	disables       map[string]*toolsRender.TextTemplate
	processors     *common.Processors
}

type SignalSinkObject struct {
	sinkMap common.SinkMap
	signal  *Signal
}

type SignalFileCache struct {
	Content      interface{}
	ModifiedTime time.Time
	contentHash  string
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

// ".templates/*.yml"
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

func (s *Signal) getFiles(vars map[string]string) map[string]*common.File {
	files := make(map[string]*common.File)
	if s.filesTemplate == nil {
		return files
	}

	fs := s.render(s.filesTemplate, s.options.Files, vars)
	kv := utils.MapGetKeyValues(fs)
	for k, v := range kv {
		if utils.FileExists(v) {
			typ := strings.Replace(filepath.Ext(v), ".", "", 1)

			pathHash := common.Md5ToString([]byte(v))
			if utils.IsEmpty(pathHash) {
				continue
			}

			fileInfo, err := os.Stat(v)
			if err != nil {
				s.logger.Error(err)
				continue
			}
			modTime := fileInfo.ModTime()

			var obj interface{}
			needReload := true

			//  load from cache
			if cached, ok := s.files.Load(pathHash); ok {
				fileCache := cached.(SignalFileCache)

				if fileCache.ModifiedTime.Equal(modTime) {
					obj = fileCache.Content
					needReload = false
				}
			}

			if needReload {
				content, err := os.ReadFile(v)
				if err != nil {
					s.logger.Error(err)
					continue
				}
				contentHash := common.Md5ToString(content)

				// parse the file based on its type
				var parseErr error
				switch {
				case typ == "json":
					obj, parseErr = common.ReadJson(content)
				case typ == "toml":
					obj, parseErr = common.ReadToml(content)
				case (typ == "yaml") || (typ == "yml"):
					obj, parseErr = common.ReadYaml(content)
				default:
					obj, parseErr = common.ReadJson(content)
				}

				if parseErr != nil {
					s.logger.Error(parseErr)
					continue
				}

				s.files.Store(pathHash, SignalFileCache{
					Content:      obj,
					contentHash:  contentHash,
					ModifiedTime: modTime,
				})
			}

			if obj != nil {
				files[k] = &common.File{
					Path: v,
					Type: typ,
					Obj:  obj,
				}
			}
		}
	}
	return files
}

func (s *Signal) expandDisabled(files map[string]*common.File, vars map[string]string) []string {

	r := make([]string, 0)
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

		arr := make([]string, 0)
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

func (s *Signal) checkDisabled(disabled []string, ident string) (bool, string) {

	for _, v := range disabled {

		match, _ := regexp.MatchString(v, ident)
		if match {
			return true, v
		}
	}
	return false, ""
}

func (s *Signal) filterVectors(name string, config *common.BaseConfig, vectors []*common.PrometheusResponseDataVector) []*common.PrometheusResponseDataVector {

	var r []*common.PrometheusResponseDataVector
	for _, v := range vectors {
		found := false
		n := v.Labels[name]
		if !utils.IsEmpty(n) {
			exists := config.Contains(n)
			found = exists
		}
		if found {
			r = append(r, v)
		}
	}
	return r
}

func (sc *SignalCache) fRegexMatchObjectByFieldCached(obj interface{}, field, value, cacheKey string) interface{} {

	if obj == nil || utils.IsEmpty(field) || utils.IsEmpty(value) {
		return nil
	}
	if sc.cache == nil || sc.template == nil {
		return ""
	}
	key := fmt.Sprintf("%s.%s.%s", field, value, cacheKey)

	entry, err := sc.cache.Get(key)
	if err == nil {

		ks := string(entry)

		a, ok := obj.([]interface{})
		ka, err := strconv.Atoi(ks)
		if ok && err == nil {
			return a[ka]
		}

		m, ok := obj.(map[string]interface{})
		if ok {
			return m[ks]
		}
	}

	ki := sc.template.RegexMatchFindKey(obj, field, value)
	if ki == nil {
		return nil
	}

	ks := fmt.Sprintf("%v", ki)

	a, ok := obj.([]interface{})
	ka, err := strconv.Atoi(ks)
	if ok && err == nil {
		sc.cache.Set(key, []byte(ks))
		return a[ka]
	}

	m, ok := obj.(map[string]interface{})
	if ok {
		sc.cache.Set(key, []byte(ks))
		return m[ks]
	}
	return nil
}

func NewSignalCache(logger sreCommon.Logger, s *Signal) *SignalCache {

	config := bigcache.DefaultConfig(time.Second * 10)
	config.MaxEntriesInWindow = 2000
	config.MaxEntrySize = 100
	if s.options.CacheSize > 0 {
		config.HardMaxCacheSize = s.options.CacheSize
	}

	cache, err := bigcache.NewBigCache(config)
	if err != nil {
		logger.Error(err)
		return nil
	}

	return &SignalCache{
		logger: logger,
		cache:  cache,
	}
}

func (s *Signal) findObjects(objects map[string]*common.Object, vectors []*common.PrometheusResponseDataVector, path string, config *common.BaseConfig) map[string]*common.Object {

	matched := objects
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

	cache := NewSignalCache(s.logger, s)

	funcs := make(map[string]any)
	funcs["regexMatchObjectByFieldCached"] = cache.fRegexMatchObjectByFieldCached

	varsOpts := toolsRender.TemplateOptions{
		Content:     s.options.Vars,
		Name:        "signal-vars",
		Funcs:       funcs,
		FilterFuncs: true,
	}
	varsTemplate, err := toolsRender.NewTextTemplate(varsOpts, s.observability)
	if err != nil {
		s.logger.Error(err)
		return nil
	}

	cache.template = varsTemplate

	s.files.Range(func(key any, value any) bool {
		s.files.Delete(key)
		return true
	})

	vectors = s.filterVectors(name, config, vectors)
	s.logger.Debug("[%d] %s: %d series filtered to %d", gid, s.source, l, len(vectors))

	when := time.Now()
	vMax := len(vectors) / 100

	var t0 time.Duration
	var t1 time.Duration
	var t2 time.Duration
	var t3 time.Duration
	var t4 time.Duration
	var tdiff time.Duration

	for i, v := range vectors {

		w := time.Now()

		if vMax > 0 && i%vMax == 0 && i > 0 {
			tsince := time.Since(when)
			s.logger.Debug("[%d] source: %s scope: %s %d out of %d [%s: %s, t0=%s t1=%s t2=%s t3=%s t4=%s]", gid, s.source, config.Labels["scope"], i, len(vectors), tsince, tsince-tdiff, t0, t1, t2, t3, t4)
			t0 = 0
			t1 = 0
			t2 = 0
			t3 = 0
			t4 = 0
			tdiff = tsince
		}

		if len(v.Labels) < 2 {
			s.logger.Debug("[%d] source: %s scope: %s No labels, min requirements (2): %v", gid, s.source, config.Labels["scope"], v.Labels)
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

		t0 = t0 + time.Since(w)
		tt := time.Since(w)

		vars := s.render(varsTemplate, s.options.Vars, m)
		objectVars := utils.MapGetKeyValues(vars)
		mergedVars := common.MergeStringMaps(v.Labels, objectVars)

		t1 = t1 + time.Since(w) - tt
		tt = time.Since(w)

		ident := ""
		field := ""

		if utils.IsEmpty(s.options.Ident) && (len(v.Labels) > 1) {
			flag := false
			for _, m := range v.Labels {
				if flag {
					ident = m
					break
				}
				flag = true
			}
		} else {
			temp := s.render(s.objectTemplate, s.options.Ident, mergedVars)
			if temp == s.options.Ident {
				ident = mergedVars[temp]
			} else {
				ident = temp
			}
		}

		t2 = t2 + time.Since(w) - tt
		tt = time.Since(w)

		temp := s.render(s.fieldTemplate, s.options.Field, mergedVars)
		if temp == s.options.Field {
			field = mergedVars[temp]
		} else {
			field = temp
		}

		metric := mergedVars[name]

		if utils.IsEmpty(ident) || utils.IsEmpty(metric) {
			s.logger.Debug("[%d] source: %s scope: %s No object, field or metric found in labels, but: %v", gid, s.source, config.Labels["scope"], mergedVars)
			continue
		}

		t3 = t3 + time.Since(w) - tt
		tt = time.Since(w)

		// find objects in files
		// if it's disabled, skip it with warning
		fieldAndIdent := fmt.Sprintf("%s/%s", field, ident)

		disabled := s.expandDisabled(fls, mergedVars)
		dis, _ := s.checkDisabled(disabled, ident)
		if dis {
			//s.logger.Trace("%s: %s disabled by pattern: %s", s.source, fieldAndIdent, pattern)
			continue
		}

		t4 = t4 + time.Since(w) - tt

		exists := config.MetricExists(metric, mergedVars)
		if !exists {
			continue
		}

		ds := matched[fieldAndIdent]
		if ds == nil {
			s.logger.Debug("[%d] source: %s scope: %s %s found by: %v [%s]", gid, s.source, config.Labels["scope"], fieldAndIdent, mergedVars, time.Since(when))
			ds = &common.Object{
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
		for k, l := range objectVars {
			if (ds.Vars[k] == "") && (l != metric) {
				ds.Vars[k] = l
			}
		}
		ds.Files = fls
		matched[fieldAndIdent] = ds
	}
	return matched
}

func (s *Signal) Discover() {

	configs := s.readBaseConfigs()
	objects := make(map[string]*common.Object)
	for path, config := range configs {
		result := make([]*common.PrometheusResponseDataVector, 0)

		if config.Disabled {
			continue
		}

		query := s.options.Query
		m := regexp.MustCompile(`^(.*)(DISCOVERY_SIGNAL_SCOPES)(.*)$`)
		str := fmt.Sprintf("${1}%s${3}", config.Scopes)
		s.prometheusOpts.Query = m.ReplaceAllString(query, str)

		if len(config.Params) > 0 {
			m = regexp.MustCompile(`^(.*)(DISCOVERY_SIGNAL_PARAMS)(.*)$`)
			str = fmt.Sprintf("${1}%s${3}", config.Params)
		} else {
			m = regexp.MustCompile(`^(.*)(,DISCOVERY_SIGNAL_PARAMS)(.*)$`)
			str = fmt.Sprintf("${1}%s${3}", "")
		}
		s.prometheusOpts.Query = m.ReplaceAllString(s.prometheusOpts.Query, str)

		s.logger.Debug("%s: Signal template %s discovery by query: %s", s.source, path, s.prometheusOpts.Query)

		if !utils.IsEmpty(s.options.QueryPeriod) {
			// https://Signal.io/docs/Signal/latest/querying/api/#range-queries
			t := time.Now().UTC()
			s.prometheusOpts.From = common.ParsePeriodFromNow(s.options.QueryPeriod, t)
			s.prometheusOpts.To = strconv.Itoa(int(t.Unix()))
			s.prometheusOpts.Step = s.options.QueryStep
			if utils.IsEmpty(s.prometheusOpts.Step) {
				s.prometheusOpts.Step = "15s"
			}
			s.logger.Debug("%s: Signal template discovery range: %s <-> %s", s.source, s.prometheusOpts.From, s.prometheusOpts.To)
		}
		var res common.PrometheusResponse
		data, err := s.prometheus.CustomGet(s.prometheusOpts)
		if err != nil {
			s.logger.Error(err)
			continue
		} else {
			err = json.Unmarshal(data, &res)

			temp := res.Data.Result
			result = append(result, temp...)
		}

		if res.Status != "success" {
			s.logger.Error(res.Status)
		}

		if (res.Data == nil) || (len(res.Data.Result) == 0) {
			s.logger.Error("%s: Signal empty data on response", s.source)
		}

		if !utils.Contains([]string{"vector", "matrix"}, res.Data.ResultType) {
			s.logger.Error("%s: Signal only vector and matrix are allowed", s.source)
		}

		objects = s.findObjects(objects, res.Data.Result, path, config)
	}
	if len(objects) == 0 {
		s.logger.Debug("%s: Signal not found any objects according query", s.source)
		return
	}

	s.processors.Process(s, &SignalSinkObject{
		sinkMap: common.ConvertObjectsToSinkMap(objects),
		signal:  s,
	})
}

func NewSignal(source string, prometheusOptions common.PrometheusOptions, options SignalOptions, observability *common.Observability, processors *common.Processors) *Signal {

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

	objectOpts := toolsRender.TemplateOptions{
		Content:     options.Ident,
		Name:        "signal-ident",
		FilterFuncs: true,
	}
	objectTemplate, err := toolsRender.NewTextTemplate(objectOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	fieldOpts := toolsRender.TemplateOptions{
		Content:     options.Field,
		Name:        "signal-field",
		FilterFuncs: true,
	}
	fieldTemplate, err := toolsRender.NewTextTemplate(fieldOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	filesOpts := toolsRender.TemplateOptions{
		Content:     options.Files,
		Name:        "signal-fiels",
		FilterFuncs: true,
	}
	filesTemplate, err := toolsRender.NewTextTemplate(filesOpts, observability)
	if err != nil {
		logger.Error(err)
	}

	prometheusOpts := toolsVendors.PrometheusOptions{
		URL:      prometheusOptions.URL,
		User:     prometheusOptions.User,
		Password: prometheusOptions.Password,
		Timeout:  prometheusOptions.Timeout,
		Insecure: prometheusOptions.Insecure,
	}

	signal := &Signal{
		source:         source,
		prometheus:     toolsVendors.NewPrometheus(prometheusOpts),
		prometheusOpts: prometheusOpts,
		options:        options,
		logger:         logger,
		observability:  observability,
		objectTemplate: objectTemplate,
		fieldTemplate:  fieldTemplate,
		filesTemplate:  filesTemplate,
		files:          &sync.Map{},
		disables:       make(map[string]*toolsRender.TextTemplate),
		processors:     processors,
	}

	return signal
}
