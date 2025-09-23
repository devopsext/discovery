package sink

import (
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	"github.com/devopsext/discovery/telegraf"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"github.com/jinzhu/copier"
)

type TelegrafSignalOptions struct {
	telegraf.InputPrometheusHttpOptions
	Dir            string
	File           string
	Tags           string
	Exclusion      string
	PersistMetrics bool
}

type TelegrafCertOptions struct {
	telegraf.InputX509CertOptions
	Template string
	Conf     string
}

type TelegrafDNSOptions struct {
	telegraf.InputDNSQueryOptions
	Template string
	Conf     string
}

type TelegrafHTTPOptions struct {
	telegraf.InputHTTPResponseOptions
	Template string
	Conf     string
}

type TelegrafTCPOptions struct {
	telegraf.InputNetResponseOptions
	Template string
	Conf     string
}

type TelegrafOptions struct {
	Providers []string
	Signal    TelegrafSignalOptions
	Cert      TelegrafCertOptions
	DNS       TelegrafDNSOptions
	HTTP      TelegrafHTTPOptions
	TCP       TelegrafTCPOptions
	Checksum  bool
}

type Telegraf struct {
	options       TelegrafOptions
	logger        sreCommon.Logger
	observability *common.Observability
}

func (t *Telegraf) Name() string {
	return "Telegraf"
}

func (t *Telegraf) Providers() []string {
	return t.options.Providers
}

func (t *Telegraf) processSignal(d common.Discovery, sm common.SinkMap, so interface{}) error {

	opts, ok := so.(discovery.SignalOptions)
	if !ok {
		return errors.New("no options")
	}

	m := common.ConvertSinkMapToObjects(sm)
	source := d.Source()

	files := make(map[string]string)
	dirs := make([]string, 0)
	identObjects := make(map[string]*common.Object)

	for _, s1 := range m {
		dir := common.Render(t.options.Signal.Dir, s1.Vars, t.observability)
		if !utils.Contains(dirs, dir) {
			dirs = append(dirs, dir)
			fls, _ := os.ReadDir(dir)
			for _, f := range fls {
				if f.IsDir() {
					continue
				}
				fPath := path.Join(dir, f.Name())
				files[fPath] = dir
			}
		}
	}

	// First pass: group objects by identField and ident and merge metrics (we need it to remove instances duplicates)
	for k, s1 := range m {
		ident, ok := s1.Vars["ident"]
		if !ok {
			t.logger.Error("%s: missing 'ident' in Vars for key: %s", source, k)
			continue
		}
		fieldIdent, ok := s1.Vars["fieldIdent"]
		if !ok {
			t.logger.Error("%s: missing 'fieldIdent' in Vars for key: %s", source, k)
			continue
		}

		fieldIdentValue := fmt.Sprintf("%s/%s", fieldIdent, ident)

		existingObj, exists := identObjects[fieldIdentValue]
		if !exists {
			// Create a new object for this ident
			identObjects[fieldIdentValue] = &common.Object{
				Metrics: append([]string{}, s1.Metrics...),
				Vars:    s1.Vars,
				Configs: s1.Configs,
				Files:   s1.Files,
			}
			continue
		}

		// Merge metrics with existing object
		for _, metric := range s1.Metrics {
			if !utils.Contains(existingObj.Metrics, metric) {
				existingObj.Metrics = append(existingObj.Metrics, metric)
			}
		}
		// Merge Configs with existing object
		for path := range s1.Configs {
			if _, exists := existingObj.Configs[path]; !exists {
				existingObj.Configs[path] = s1.Configs[path]
			}
		}
		// Update other fields (keep the latest vars, files)
		existingObj.Vars = s1.Vars
		existingObj.Files = s1.Files
	}

	// Second pass: process merged objects
	for ident, s1 := range identObjects {

		dir := common.Render(t.options.Signal.Dir, s1.Vars, t.observability)
		file := common.Render(t.options.Signal.File, s1.Vars, t.observability)
		fPath := path.Join(dir, file)

		delete(files, fPath)

		t.logger.Debug("%s: Processing application: %s for path: %s", source, ident, fPath)
		t.logger.Debug("%s: Found metrics: %v", source, s1.Metrics)

		telegrafConfig := &telegraf.Config{
			Observability: t.observability,
		}

		inputOpts := telegraf.InputPrometheusHttpOptions{}
		err := copier.CopyWithOption(&inputOpts, &t.options.Signal.InputPrometheusHttpOptions, copier.Option{IgnoreEmpty: true, DeepCopy: true})
		if err != nil {
			t.logger.Error("%s: application %s error: %s", source, ident, err)
			continue
		}
		inputOpts.URL = opts.URL
		inputOpts.User = opts.User
		inputOpts.Password = opts.Password

		bytes, err := telegrafConfig.GenerateInputPrometheusHttpBytes(s1, t.options.Signal.Tags, inputOpts, fPath, t.options.Signal.PersistMetrics)
		if err != nil {
			t.logger.Error("%s: application %s error: %s", source, ident, err)
			continue
		}
		telegrafConfig.CreateIfCheckSumIsDifferent(source, fPath, t.options.Checksum, bytes, t.logger)
	}

	if len(files) > 0 {

		var reExclusion *regexp.Regexp
		exclusion := t.options.Signal.Exclusion
		if !utils.IsEmpty(exclusion) {
			re, err := regexp.Compile(exclusion)
			if err != nil {
				t.logger.Error("%s: exclusion %s error: %s", source, exclusion, err)
			} else {
				reExclusion = re
			}
		}

		for k := range files {

			remove := true
			if reExclusion != nil {
				remove = !reExclusion.MatchString(k)
			}
			if remove {
				err := os.Remove(k)
				if err != nil {
					t.logger.Error("%s: remove %s error: %s", source, k, err)
				}
			}
		}
	}

	return nil
}

func (t *Telegraf) processCert(d common.Discovery, sm common.SinkMap) error {

	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	m := common.ConvertSinkMapToLabelsMap(sm)
	bs, err := telegrafConfig.GenerateInputX509CertBytes(t.options.Cert.InputX509CertOptions, m)
	if err != nil {
		return err
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(d.Source(), t.options.Cert.Template, t.options.Cert.Conf, t.options.Checksum, bs, t.logger)
	return nil
}

func (t *Telegraf) processDNS(d common.Discovery, sm common.SinkMap) error {

	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	m := common.ConvertSinkMapToLabelsMap(sm)
	bs, err := telegrafConfig.GenerateInputDNSQueryBytes(t.options.DNS.InputDNSQueryOptions, m)
	if err != nil {
		return err
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(d.Source(), t.options.DNS.Template, t.options.DNS.Conf, t.options.Checksum, bs, t.logger)
	return nil
}

func (t *Telegraf) processHTTP(d common.Discovery, sm common.SinkMap) error {

	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	m := common.ConvertSinkMapToLabelsMap(sm)
	bs, err := telegrafConfig.GenerateInputHTTPResponseBytes(t.options.HTTP.InputHTTPResponseOptions, m)
	if err != nil {
		return err
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(d.Source(), t.options.HTTP.Template, t.options.HTTP.Conf, t.options.Checksum, bs, t.logger)
	return nil
}

func (t *Telegraf) processTCP(d common.Discovery, sm common.SinkMap) error {

	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	m := common.ConvertSinkMapToLabelsMap(sm)
	bs, err := telegrafConfig.GenerateInputNETResponseBytes(t.options.TCP.InputNetResponseOptions, m, "tcp")
	if err != nil {
		return err
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(d.Source(), t.options.TCP.Template, t.options.TCP.Conf, t.options.Checksum, bs, t.logger)
	return nil
}

func (t *Telegraf) Process(d common.Discovery, so common.SinkObject) {

	dname := d.Name()
	m := so.Map()
	t.logger.Debug("Telegraf has to process %d objects from %s...", len(m), dname)
	var err error

	switch dname {
	case "Signal":
		err = t.processSignal(d, m, so.Options())
	case "Cert":
		err = t.processCert(d, m)
	case "DNS":
		err = t.processDNS(d, m)
	case "HTTP":
		err = t.processHTTP(d, m)
	case "TCP":
		err = t.processTCP(d, m)
	default:
		t.logger.Debug("Telegraf has no support for %s", dname)
		return
	}

	if err != nil {
		t.logger.Error("Telegraf process %s from %s error: %s", dname, d.Source(), err)
		return
	}
}

func NewTelegraf(options TelegrafOptions, observability *common.Observability) *Telegraf {

	logger := observability.Logs()
	options.Providers = common.RemoveEmptyStrings(options.Providers)

	return &Telegraf{
		options:       options,
		logger:        logger,
		observability: observability,
	}
}
