package discovery

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"gopkg.in/fsnotify.v1"

	"github.com/itchyny/gojq"
)

type FileProvider struct {
	name   string
	path   string
	query  string
	obj    interface{}
	logger sreCommon.Logger
}

type FileProviders struct {
	list       map[string]string
	converters map[string]string
}

type FilesOptions struct {
	Folder     string
	Providers  string
	Converters string
}

type Files struct {
	options       FilesOptions
	logger        sreCommon.Logger
	observability *common.Observability
	processors    *common.Processors
	watcher       *fsnotify.Watcher
	provideres    *FileProviders
}

type FilesSinkObject struct {
	sinkMap common.SinkMap
	Files   *Files
}

// FileProvider
func (p *FileProvider) Name() string {
	return p.name
}

func (p *FileProvider) Source() string {
	return ""
}

func (p *FileProvider) Discover() {
	// dumb method
}

func (p *FileProvider) filter(obj interface{}, q string) interface{} {

	if utils.IsEmpty(q) {
		return obj
	}

	// https://itchyny.medium.com/golang-implementation-of-jq-gojq-ad5bd46a4af2
	// https://github.com/jqlang/jq/blob/ccc79e592cfe1172db5f2def5a24c2f7cfd418bf/src/builtin.jq
	//q = "match_keys(\"group|name|tier\")"

	funcs := []string{
		"def map(f): [.[] | f]",
		"def select(f): if f then . else empty end",
		"def with_entries(f): to_entries | map(f) | from_entries",
		"def map_values(f): .[] |= f",
		"def match(re; mode): _match(re; mode; false)|.[]",
		"def match_keys(f): map_values(with_entries(select(.key | match (f))))",
		q,
	}

	q1 := strings.Join(funcs, ";\n")

	query, err := gojq.Parse(q1)
	if err != nil {
		p.logger.Error("Files couldn't filter object error: %s", err)
		return obj
	}

	var arr []interface{}
	iter := query.Run(obj)
	for {
		v, ok := iter.Next()
		if !ok {
			if len(arr) == 1 {
				return arr[0]
			}
			break
		}
		if err, ok := v.(error); ok {
			var haltErr *gojq.HaltError
			if errors.As(err, &haltErr) && haltErr.Value() == nil {
				break
			}
			p.logger.Error("Files couldn't filter object error: %s", err)
		}
		arr = append(arr, v)
	}
	return arr
}

func (p *FileProvider) Map() common.SinkMap {

	def := make(common.SinkMap)
	if p.obj == nil {
		return def
	}

	m, ok := p.obj.(map[string]interface{})
	if !ok {
		return def
	}

	obj := p.filter(m, p.query)
	m2, ok := obj.(map[string]interface{})
	if !ok {
		return def
	}

	lbsm := make(common.LabelsMap)
	for k, v := range m2 {

		mv, ok := v.(map[string]interface{})
		if !ok {
			continue
		}

		lbs := make(common.Labels)
		for k1, v1 := range mv {
			lbs[k1] = fmt.Sprintf("%v", v1)
		}
		lbsm[k] = lbs
	}

	return common.ConvertLabelsMapToSinkMap(lbsm)
}

func (p *FileProvider) Options() interface{} {
	return nil
}

// FileProviders
func (fp *FileProviders) readJson(bytes []byte) (interface{}, error) {

	var v interface{}
	err := json.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (fp *FileProviders) discover(provider, path string, logger sreCommon.Logger) (*FileProvider, error) {

	tp := strings.Replace(filepath.Ext(path), ".", "", 1)

	var bytes []byte
	var err error

	switch tp {
	case "json":
		bytes, err = os.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}

	obj, err := fp.readJson(bytes)
	if err != nil {
		return nil, err
	}

	p := &FileProvider{
		name:   provider,
		path:   path,
		query:  fp.converters[provider],
		obj:    obj,
		logger: logger,
	}
	return p, nil
}

// FilesSinkObject
func (do *FilesSinkObject) Map() common.SinkMap {
	return do.sinkMap
}

func (do *FilesSinkObject) Options() interface{} {
	return do.Files.options
}

// Files
func (d *Files) Name() string {
	return "Files"
}

func (d *Files) Source() string {
	return ""
}

func (d *Files) discoverProviders(m map[string]interface{}) {

	for provider, file := range d.provideres.list {
		path := m[file]
		if path == nil {
			continue
		}
		fp, err := d.provideres.discover(provider, path.(string), d.logger)
		if err != nil {
			d.logger.Error("Files couldn't discover provider by %s due to error: %s", file, err)
			continue
		}
		d.processors.Process(fp, fp)
	}
}

func (d *Files) Discover() {

	d.logger.Debug("Files discovery by folder: %s", d.options.Folder)

	m := make(common.SinkMap)

	folders := common.RemoveEmptyStrings(strings.Split(d.options.Folder, ","))
	for _, v := range folders {
		err := d.watcher.Add(v)
		if err != nil {
			d.logger.Error("Files couldn't watch folder: %s due to error: %s", v, err)
		}
		err = filepath.Walk(v, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				name := filepath.Base(path)
				m[name] = path
			}
			return nil
		})
		if err != nil {
			d.logger.Error("Files couldn't walk folder: %s due to error: %s", v, err)
		}
	}

	// run it first
	if len(m) > 0 {
		d.processors.Process(d, &FilesSinkObject{
			sinkMap: m,
			Files:   d,
		})
		d.discoverProviders(m)
	}

	for {
		select {
		case event, ok := <-d.watcher.Events:
			if !ok {
				return
			}
			d.logger.Debug("Files watcher event (%d): %s", event.Op, event.Name)
			if (event.Op == fsnotify.Create) || (event.Op == fsnotify.Write) || (event.Op == fsnotify.Chmod) {

				if !utils.FileExists(event.Name) {
					continue
				}
				name := filepath.Base(event.Name)
				m[name] = event.Name
				d.processors.Process(d, &FilesSinkObject{
					sinkMap: m,
					Files:   d,
				})
				d.discoverProviders(m)
			}
		case err, ok := <-d.watcher.Errors:
			d.logger.Error("Files watcher has error: %s", err)
			if !ok {
				continue
			}
		}
	}
}

func NewFiles(options FilesOptions, observability *common.Observability, processors *common.Processors) *Files {

	logger := observability.Logs()

	if utils.IsEmpty(options.Folder) {
		logger.Debug("Files has no folder. Skipped")
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Error("Files couldn't create watcher: %s", err)
		return nil
	}

	return &Files{
		options:       options,
		logger:        logger,
		observability: observability,
		processors:    processors,
		watcher:       watcher,
		provideres: &FileProviders{
			list:       utils.MapGetKeyValues(options.Providers),
			converters: utils.MapGetKeyValues(options.Converters),
		},
	}
}
