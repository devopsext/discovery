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

type DirOptions struct {
	toolsVendors.ZabbixOptions
	Folder string
}

type Dir struct {
	options       DirOptions
	logger        sreCommon.Logger
	observability *common.Observability
	sinks         *common.Sinks
	watcher       *fsnotify.Watcher
}

type DirSinkObject struct {
	sinkMap common.SinkMap
	dir     *Dir
}

func (do *DirSinkObject) Map() common.SinkMap {
	return do.sinkMap
}

func (do *DirSinkObject) Options() interface{} {
	return do.dir.options
}

func (d *Dir) Name() string {
	return "Dir"
}

func (d *Dir) Source() string {
	return ""
}

func (d *Dir) Discover() {

	d.logger.Debug("Dir discovery by folder: %s", d.options.Folder)

	m := make(common.SinkMap)

	folders := common.RemoveEmptyStrings(strings.Split(d.options.Folder, ","))
	for _, v := range folders {
		err := d.watcher.Add(v)
		if err != nil {
			d.logger.Error("Dir couldn't watch folder: %s due to error: %s", v, err)
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
		d.sinks.Process(d, &DirSinkObject{
			sinkMap: m,
			dir:     d,
		})
	}

	for {
		select {
		case event, ok := <-d.watcher.Events:
			if !ok {
				return
			}
			d.logger.Debug("Dir watcher event (%d): %s", event.Op, event.Name)
			if (event.Op == fsnotify.Create) || (event.Op == fsnotify.Write) || (event.Op == fsnotify.Chmod) {

				name := filepath.Base(event.Name)
				m := make(common.SinkMap)
				m[name] = event.Name
				d.sinks.Process(d, &DirSinkObject{
					sinkMap: m,
					dir:     d,
				})
			}
		case err, ok := <-d.watcher.Errors:
			if !ok {
				return
			}
			d.logger.Error("Dir watcher has error: %s", err)
		}
	}
}

func NewDir(options DirOptions, observability *common.Observability, sinks *common.Sinks) *Dir {

	logger := observability.Logs()

	if utils.IsEmpty(options.Folder) {
		logger.Debug("Dir has no folder. Skipped")
		return nil
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Error("Dir couldn't create watcher: %s", err)
		return nil
	}

	return &Dir{
		options:       options,
		logger:        logger,
		observability: observability,
		sinks:         sinks,
		watcher:       watcher,
	}
}
