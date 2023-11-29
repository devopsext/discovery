package sink

import (
	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	telegraf "github.com/devopsext/discovery/telegraf"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/pkg/errors"
)

type TelegrafOptions struct {
	Pass []string
}

type Telegraf struct {
	options       TelegrafOptions
	logger        sreCommon.Logger
	observability *common.Observability
}

func (t *Telegraf) Name() string {
	return "Telegraf"
}

func (t *Telegraf) Pass() []string {
	return t.options.Pass
}

// .telegraf/prefix-{{.namespace}}-discovery-{{.service}}-{{.container_name}}{{.container}}.conf
func (t *Telegraf) processSignal(d common.Discovery, so common.SinkObject) error {

	opts, ok := so.Options().(discovery.SignalOptions)
	if !ok {
		return errors.New("No options")
	}

	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	m := common.ConvertSyncMapToServices(so.Map())
	source := d.Source()

	for k, s1 := range m {

		path := common.Render(opts.TelegrafTemplate, s1.Vars, t.observability)
		t.logger.Debug("%s: Processing service: %s for path: %s", source, k, path)
		t.logger.Debug("%s: Found metrics: %v", source, s1.Metrics)

		bytes, err := telegrafConfig.GenerateInputPrometheusHttpBytes(s1, opts.TelegrafTags, opts.TelegrafOptions, path)
		if err != nil {
			t.logger.Error("%s: Service %s error: %s", source, k, err)
			continue
		}
		telegrafConfig.CreateIfCheckSumIsDifferent(source, path, opts.TelegrafChecksum, bytes, t.logger)
	}

	return nil
}

func (t *Telegraf) processCert(d common.Discovery, so common.SinkObject) error {

	opts, ok := so.Options().(discovery.CertOptions)
	if !ok {
		return errors.New("No options")
	}
	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	m := common.ConvertSyncMapToLabelsMap(so.Map())
	bs, err := telegrafConfig.GenerateInputX509CertBytes(opts.TelegrafOptions, m)
	if err != nil {
		return err
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(d.Source(), opts.TelegrafTemplate, opts.TelegrafConf, opts.TelegrafChecksum, bs, t.logger)
	return nil
}

func (t *Telegraf) processDNS(d common.Discovery, so common.SinkObject) error {

	opts, ok := so.Options().(discovery.DNSOptions)
	if !ok {
		return errors.New("No options")
	}
	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	m := common.ConvertSyncMapToLabelsMap(so.Map())
	bs, err := telegrafConfig.GenerateInputDNSQueryBytes(opts.TelegrafOptions, m)
	if err != nil {
		return err
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(d.Source(), opts.TelegrafTemplate, opts.TelegrafConf, opts.TelegrafChecksum, bs, t.logger)
	return nil
}

func (t *Telegraf) processHTTP(d common.Discovery, so common.SinkObject) error {

	opts, ok := so.Options().(discovery.HTTPOptions)
	if !ok {
		return errors.New("No options")
	}
	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	m := common.ConvertSyncMapToLabelsMap(so.Map())
	bs, err := telegrafConfig.GenerateInputHTTPResponseBytes(opts.TelegrafOptions, m)
	if err != nil {
		return err
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(d.Source(), opts.TelegrafTemplate, opts.TelegrafConf, opts.TelegrafChecksum, bs, t.logger)
	return nil
}

func (t *Telegraf) processTCP(d common.Discovery, so common.SinkObject) error {

	opts, ok := so.Options().(discovery.TCPOptions)
	if !ok {
		return errors.New("No options")
	}
	telegrafConfig := &telegraf.Config{
		Observability: t.observability,
	}
	m := common.ConvertSyncMapToLabelsMap(so.Map())
	bs, err := telegrafConfig.GenerateInputNETResponseBytes(opts.TelegrafOptions, m, "tcp")
	if err != nil {
		return err
	}
	telegrafConfig.CreateWithTemplateIfCheckSumIsDifferent(d.Source(), opts.TelegrafTemplate, opts.TelegrafConf, opts.TelegrafChecksum, bs, t.logger)
	return nil
}

func (t *Telegraf) Process(d common.Discovery, so common.SinkObject) {

	dname := d.Name()
	m := so.Map()
	t.logger.Debug("Telegraf has to process %d objects from %s...", len(m), dname)
	var err error

	switch dname {
	case "Signal":
		err = t.processSignal(d, so)
	case "Cert":
		err = t.processCert(d, so)
	case "DNS":
		err = t.processDNS(d, so)
	case "HTTP":
		err = t.processHTTP(d, so)
	case "TCP":
		err = t.processTCP(d, so)
	default:
		t.logger.Debug("Telegraf has no support for %s", dname)
		return
	}

	if err != nil {
		t.logger.Error("%s: %s query error: %s", d.Source(), dname, err)
		return
	}
}

func NewTelegraf(options TelegrafOptions, observability *common.Observability) *Telegraf {

	logger := observability.Logs()
	options.Pass = common.RemoveEmptyStrings(options.Pass)

	return &Telegraf{
		options:       options,
		logger:        logger,
		observability: observability,
	}
}
