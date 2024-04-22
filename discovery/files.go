package discovery

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"gopkg.in/fsnotify.v1"
)

type FilesOptions struct {
	toolsVendors.ZabbixOptions
	Folder string
}

type Files struct {
	options       FilesOptions
	logger        sreCommon.Logger
	observability *common.Observability
	sinks         *common.Sinks
	watcher       *fsnotify.Watcher
}

type FilesSinkObject struct {
	sinkMap common.SinkMap
	Files   *Files
}

func (do *FilesSinkObject) Map() common.SinkMap {
	return do.sinkMap
}

func (do *FilesSinkObject) Options() interface{} {
	return do.Files.options
}

func (d *Files) Name() string {
	return "Files"
}

func (d *Files) Source() string {
	return ""
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
		filepath.Walk(v, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				name := filepath.Base(path)
				m[name] = path
			}
			return nil
		})
	}

	if len(m) > 0 {
		d.sinks.Process(d, &FilesSinkObject{
			sinkMap: m,
			Files:   d,
		})
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
					return
				}
				name := filepath.Base(event.Name)
				m := make(common.SinkMap)
				m[name] = event.Name
				d.sinks.Process(d, &FilesSinkObject{
					sinkMap: m,
					Files:   d,
				})
			}
		case err, ok := <-d.watcher.Errors:
			if !ok {
				return
			}
			d.logger.Error("Files watcher has error: %s", err)
		}
	}
}

func NewFiles(options FilesOptions, observability *common.Observability, sinks *common.Sinks) *Files {

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
		sinks:         sinks,
		watcher:       watcher,
	}
}
