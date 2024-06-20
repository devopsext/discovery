package processor

import (
	"path/filepath"
	"strings"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	toolsRender "github.com/devopsext/tools/render"
	"github.com/devopsext/utils"
)

type TemplateOptions struct {
	Content   string
	Files     string
	Providers []string
}

type Template struct {
	options       TemplateOptions
	logger        sreCommon.Logger
	observability *common.Observability
	tpl           *toolsRender.TextTemplate
}

func (t *Template) Name() string {
	return "Template"
}

func (t *Template) Providers() []string {
	return t.options.Providers
}

func (t *Template) render(name string, files map[string]interface{}, sm common.SinkMap) error {

	m := make(map[string]interface{})
	m["name"] = name
	m["files"] = files
	m["fields"] = sm

	_, err := t.tpl.RenderObject(m)
	if err != nil {
		return err
	}
	return nil
}

func (t *Template) loadFiles() map[string]interface{} {

	files := make(map[string]interface{})

	list := utils.MapGetKeyValues(t.options.Files)

	for k, v := range list {

		if utils.FileExists(v) {

			typ := strings.Replace(filepath.Ext(v), ".", "", 1)
			obj, err := common.ReadFile(v, typ)
			if err != nil {
				t.logger.Error(err)
				continue
			}

			if obj != nil {
				files[k] = obj
			}
		}
	}
	return files
}

func (t *Template) Process(d common.Discovery, so common.SinkObject) {

	files := t.loadFiles()

	err := t.render(d.Name(), files, so.Map())
	if err != nil {
		t.logger.Error(err)
	}
}

func templateSetCommonLabelValue(labels common.Labels, key, value string) string {

	if utils.IsEmpty(labels) {
		return ""
	}
	labels[key] = value
	return ""
}

func templateGetCommonLabelValue(labels common.Labels, key string) string {

	if utils.IsEmpty(labels) {
		return ""
	}
	return labels[key]
}

func NewTemplate(options TemplateOptions, observability *common.Observability, sinks *common.Sinks) *Template {

	logger := observability.Logs()
	options.Providers = common.RemoveEmptyStrings(options.Providers)

	if utils.IsEmpty(options.Content) {
		logger.Debug("Template has no content. Skipped")
		return nil
	}

	funcs := make(map[string]any)
	funcs["setCommonLabelValue"] = templateSetCommonLabelValue
	funcs["getCommonLabelValue"] = templateGetCommonLabelValue

	tplOpts := toolsRender.TemplateOptions{
		Content: options.Content,
		Name:    "template",
		Funcs:   funcs,
	}
	tpl, err := toolsRender.NewTextTemplate(tplOpts, observability)
	if err != nil {
		logger.Error(err)
		return nil
	}

	return &Template{
		options:       options,
		logger:        logger,
		observability: observability,
		tpl:           tpl,
	}
}
