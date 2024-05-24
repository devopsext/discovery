package sink

import (
	"errors"
	"os"
	"path"
	"regexp"
	"slices"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	telegraf "github.com/devopsext/discovery/telegraf"
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

// .telegraf/prefix-{{.namespace}}-discovery-{{.object}}-{{.container_name}}{{.container}}.conf
func (t *Telegraf) processSignal(d common.Discovery, sm common.SinkMap, so interface{}) error {

	opts, ok := so.(discovery.SignalOptions)
	if !ok {
		return errors.New("no options")
	}

	m := common.ConvertSyncMapToObjects(sm)
	source := d.Source()

	old := []string{}
	files, _ := os.ReadDir(t.options.Signal.Dir)
	for _, f := range files {
		if !f.IsDir() {
			name := path.Join(t.options.Signal.Dir, f.Name())
			old = append(old, name)
		}
	}

	for k, s1 := range m {

		file := common.Render(t.options.Signal.File, s1.Vars, t.observability)
		path := path.Join(t.options.Signal.Dir, file)

		old = slices.DeleteFunc(old, func(s string) bool {
			return s == path
		})

		t.logger.Debug("%s: Processing application: %s for path: %s", source, k, path)
		t.logger.Debug("%s: Found metrics: %v", source, s1.Metrics)

		telegrafConfig := &telegraf.Config{
			Observability: t.observability,
		}

		inputOpts := telegraf.InputPrometheusHttpOptions{}
		copier.CopyWithOption(&inputOpts, &t.options.Signal.InputPrometheusHttpOptions, copier.Option{IgnoreEmpty: true, DeepCopy: true})
		inputOpts.URL = opts.URL
		inputOpts.User = opts.User
		inputOpts.Password = opts.Password

		bytes, err := telegrafConfig.GenerateInputPrometheusHttpBytes(s1, t.options.Signal.Tags, inputOpts, path, t.options.Signal.PersistMetrics)
		if err != nil {
			t.logger.Error("%s: application %s error: %s", source, k, err)
			continue
		}
		telegrafConfig.CreateIfCheckSumIsDifferent(source, path, t.options.Checksum, bytes, t.logger)
	}

	if len(old) > 0 {

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

		for _, s := range old {

			remove := true
			if reExclusion != nil {
				remove = !reExclusion.MatchString(s)
			}
			if remove {
				os.Remove(s)
			}
		}
	}

	return nil
}

func (t *Telegraf) processCert(d common.Discovery, sm common.SinkMap) error {

	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	m := common.ConvertSyncMapToLabelsMap(sm)
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
	m := common.ConvertSyncMapToLabelsMap(sm)
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
	m := common.ConvertSyncMapToLabelsMap(sm)
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
	m := common.ConvertSyncMapToLabelsMap(sm)
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
