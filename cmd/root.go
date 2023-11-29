package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"strings"
	"time"

	"sync"
	"syscall"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	"github.com/devopsext/discovery/sink"
	"github.com/devopsext/discovery/telegraf"
	sreCommon "github.com/devopsext/sre/common"
	sreProvider "github.com/devopsext/sre/provider"
	"github.com/devopsext/tools/vendors"
	"github.com/devopsext/utils"
	"github.com/go-co-op/gocron"
	"github.com/jinzhu/copier"
	"github.com/spf13/cobra"
)

var version = "unknown"
var APPNAME = "DISCOVERY"

var logs = sreCommon.NewLogs()
var metrics = sreCommon.NewMetrics()
var stdout *sreProvider.Stdout
var mainWG sync.WaitGroup

type RootOptions struct {
	Logs    []string
	Metrics []string
	RunOnce bool
}

var rootOptions = RootOptions{
	Logs:    strings.Split(envGet("LOGS", "stdout").(string), ","),
	Metrics: strings.Split(envGet("METRICS", "prometheus").(string), ","),
	RunOnce: envGet("RUN_ONCE", false).(bool),
}

var stdoutOptions = sreProvider.StdoutOptions{
	Format:          envGet("STDOUT_FORMAT", "text").(string),
	Level:           envGet("STDOUT_LEVEL", "info").(string),
	Template:        envGet("STDOUT_TEMPLATE", "{{.file}} {{.msg}}").(string),
	TimestampFormat: envGet("STDOUT_TIMESTAMP_FORMAT", time.RFC3339Nano).(string),
	TextColors:      envGet("STDOUT_TEXT_COLORS", true).(bool),
}

var prometheusMetricsOptions = sreProvider.PrometheusOptions{
	URL:    envGet("PROMETHEUS_METRICS_URL", "/metrics").(string),
	Listen: envGet("PROMETHEUS_METRICS_LISTEN", ":8080").(string),
	Prefix: envGet("PROMETHEUS_METRICS_PREFIX", "events").(string),
}

var discoveryPrometheusOptions = common.PrometheusOptions{
	Names:    envStringExpand("PROMETHEUS_NAMES", ""),
	URL:      envStringExpand("PROMETHEUS_URL", ""),
	Timeout:  envGet("PROMETHEUS_TIMEOUT", 30).(int),
	Insecure: envGet("PROMETHEUS_INSECURE", false).(bool),
}

var discoverySignalOptions = discovery.SignalOptions{
	Disabled:     strings.Split(envStringExpand("SIGNAL_DISABLED", ""), ","),
	Schedule:     envGet("SIGNAL_SCHEDULE", "").(string),
	Query:        envFileContentExpand("SIGNAL_QUERY", ""),
	QueryPeriod:  envGet("SIGNAL_QUERY_PERIOD", "").(string),
	QueryStep:    envGet("SIGNAL_QUERY_STEP", "").(string),
	Metric:       envGet("SIGNAL_METRIC", "").(string),
	Service:      envGet("SIGNAL_SERVICE", "").(string),
	Field:        envGet("SIGNAL_FIELD", "").(string),
	Files:        envFileContentExpand("SIGNAL_FILES", ""),
	Vars:         envFileContentExpand("SIGNAL_VARS", ""),
	BaseTemplate: envStringExpand("SIGNAL_BASE_TEMPLATE", ""),

	TelegrafTags:     envFileContentExpand("SIGNAL_TELEGRAF_TAGS", ""),
	TelegrafTemplate: envStringExpand("SIGNAL_TELEGRAF_TEMPLATE", ""),
	TelegrafChecksum: envGet("SIGNAL_TELEGRAF_CHECKSUM", false).(bool),

	TelegrafOptions: telegraf.InputPrometheusHttpOptions{
		Interval:         envGet("SIGNAL_TELEGRAF_INTERVAL", "10s").(string),
		URL:              envStringExpand("SIGNAL_TELEGRAF_URL", ""),
		Version:          envGet("SIGNAL_TELEGRAF_VERSION", "v1").(string),
		Params:           envGet("SIGNAL_TELEGRAF_PARAMS", "").(string),
		Duration:         envGet("SIGNAL_TELEGRAF_DURATION", "").(string),
		Timeout:          envGet("SIGNAL_TELEGRAF_TIMEOUT", "5s").(string),
		Prefix:           envGet("SIGNAL_TELEGRAF_PREFIX", "").(string),
		QualityName:      envGet("SIGNAL_TELEGRAF_QUALITY_NAME", "quality").(string),
		QualityRange:     envGet("SIGNAL_TELEGRAF_QUALITY_RANGE", "5m").(string),
		QualityEvery:     envGet("SIGNAL_TELEGRAF_QUALITY_EVERY", "15s").(string),
		QualityPoints:    envGet("SIGNAL_TELEGRAF_QUALITY_POINTS", 20).(int),
		QualityQuery:     envFileContentExpand("SIGNAL_TELEGRAF_QUALITY_QUERY", ""),
		AvailabilityName: envGet("SIGNAL_TELEGRAF_AVAILABILITY_NAME", "availability").(string),
		MetricName:       envGet("SIGNAL_TELEGRAF_METRIC_NAME", "metric").(string),
		DefaultTags:      strings.Split(envStringExpand("SIGNAL_TELEGRAF_DEFAULT_TAGS", ""), ","),
		VarFormat:        envGet("SIGNAL_TELEGRAF_VAR_FORMAT", "$%s").(string),
	},
}

var discoveryDNSOptions = discovery.DNSOptions{
	Schedule:    envGet("DNS_SCHEDULE", "").(string),
	Query:       envFileContentExpand("DNS_QUERY", ""),
	QueryPeriod: envGet("DNS_QUERY_PERIOD", "").(string),
	QueryStep:   envGet("DNS_QUERY_STEP", "").(string),
	Pattern:     envGet("DNS_PATTERN", "").(string),
	Names:       envFileContentExpand("DNS_NAMES", ""),
	Exclusion:   envGet("DNS_EXCLUSION", "").(string),

	TelegrafConf:     envStringExpand("DNS_TELEGRAF_CONF", ""),
	TelegrafTemplate: envFileContentExpand("DNS_TELEGRAF_TEMPLATE", ""),
	TelegrafChecksum: envGet("DNS_TELEGRAF_CHECKSUM", false).(bool),

	TelegrafOptions: telegraf.InputDNSQueryOptions{
		Interval:   envGet("DNS_TELEGRAF_INTERVAL", "10s").(string),
		Servers:    envGet("DNS_TELEGRAF_SERVERS", "").(string),
		Network:    envGet("DNS_TELEGRAF_NETWORK", "upd").(string),
		RecordType: envGet("DNS_TELEGRAF_RECORD_TYPE", "A").(string),
		Port:       envGet("DNS_TELEGRAF_PORT", 53).(int),
		Timeout:    envGet("DNS_TELEGRAF_TIMEOUT", 2).(int),
		Tags:       strings.Split(envStringExpand("DNS_TELEGRAF_TAGS", ""), ","),
	},
}

var discoveryHTTPOptions = discovery.HTTPOptions{
	Schedule:    envGet("HTTP_SCHEDULE", "").(string),
	Query:       envFileContentExpand("HTTP_QUERY", ""),
	QueryPeriod: envGet("HTTP_QUERY_PERIOD", "").(string),
	QueryStep:   envGet("HTTP_QUERY_STEP", "").(string),
	Pattern:     envGet("HTTP_PATTERN", "").(string),
	Names:       envFileContentExpand("HTTP_NAMES", ""),
	Exclusion:   envGet("HTTP_EXCLUSION", "").(string),
	NoSSL:       envGet("HTTP_NO_SSL", "").(string),

	TelegrafConf:     envStringExpand("HTTP_TELEGRAF_CONF", ""),
	TelegrafTemplate: envFileContentExpand("HTTP_TELEGRAF_TEMPLATE", ""),
	TelegrafChecksum: envGet("HTTP_TELEGRAF_CHECKSUM", false).(bool),

	TelegrafOptions: telegraf.InputHTTPResponseOptions{
		Interval:        envGet("HTTP_TELEGRAF_INTERVAL", "10s").(string),
		URLs:            envGet("HTTP_TELEGRAF_URLS", "").(string),
		Path:            envFileContentExpand("HTTP_TELEGRAF_PATH", ""),
		Method:          envGet("HTTP_TELEGRAF_METHOD", "GET").(string),
		FollowRedirects: envGet("HTTP_TELEGRAF_FOLLOW_REDIRECTS", false).(bool),
		StringMatch:     envGet("HTTP_TELEGRAF_STRING_MATCH", "").(string),
		StatusCode:      envGet("HTTP_TELEGRAF_STATUS_CODE", 0).(int),
		Timeout:         envGet("HTTP_TELEGRAF_TIMEOUT", "5s").(string),
		Tags:            strings.Split(envStringExpand("HTTP_TELEGRAF_TAGS", ""), ","),
	},
}

var discoveryTCPOptions = discovery.TCPOptions{
	Schedule:    envGet("TCP_SCHEDULE", "").(string),
	Query:       envFileContentExpand("TCP_QUERY", ""),
	QueryPeriod: envGet("TCP_QUERY_PERIOD", "").(string),
	QueryStep:   envGet("TCP_QUERY_STEP", "").(string),
	Pattern:     envGet("TCP_PATTERN", "").(string),
	Names:       envFileContentExpand("TCP_NAMES", ""),
	Exclusion:   envGet("TCP_EXCLUSION", "").(string),

	TelegrafConf:     envStringExpand("TCP_TELEGRAF_CONF", ""),
	TelegrafTemplate: envFileContentExpand("TCP_TELEGRAF_TEMPLATE", ""),
	TelegrafChecksum: envGet("TCP_TELEGRAF_CHECKSUM", false).(bool),

	TelegrafOptions: telegraf.InputNetResponseOptions{
		Interval:    envGet("TCP_TELEGRAF_INTERVAL", "10s").(string),
		Timeout:     envGet("TCP_TELEGRAF_TIMEOUT", "5s").(string),
		ReadTimeout: envGet("TCP_TELEGRAF_READ_TIMEOUT", "3s").(string),
		Send:        envGet("TCP_TELEGRAF_SEND", "").(string),
		Expect:      envGet("TCP_TELEGRAF_EXPECT", "").(string),
		Tags:        strings.Split(envStringExpand("TCP_TELEGRAF_TAGS", ""), ","),
	},
}

var discoveryCertOptions = discovery.CertOptions{
	Schedule:    envGet("CERT_SCHEDULE", "").(string),
	Query:       envFileContentExpand("CERT_QUERY", ""),
	QueryPeriod: envGet("CERT_QUERY_PERIOD", "").(string),
	QueryStep:   envGet("CERT_QUERY_STEP", "").(string),
	Pattern:     envGet("CERT_PATTERN", "").(string),
	Names:       envFileContentExpand("CERT_NAMES", ""),
	Exclusion:   envGet("CERT_EXCLUSION", "").(string),

	TelegrafConf:     envStringExpand("CERT_TELEGRAF_CONF", ""),
	TelegrafTemplate: envFileContentExpand("CERT_TELEGRAF_TEMPLATE", ""),
	TelegrafChecksum: envGet("CERT_TELEGRAF_CHECKSUM", false).(bool),

	TelegrafOptions: telegraf.InputX509CertOptions{
		Interval:         envGet("CERT_TELEGRAF_INTERVAL", "10s").(string),
		Timeout:          envGet("CERT_TELEGRAF_TIMEOUT", "5s").(string),
		ServerName:       envGet("CERT_TELEGRAF_SERVER_NAME", "").(string),
		ExcludeRootCerts: envGet("CERT_TELEGRAF_EXCLUDE_ROOT_CERTS", false).(bool),
		TLSCA:            envGet("CERT_TELEGRAF_TLS_CA", "").(string),
		TLSCert:          envGet("CERT_TELEGRAF_TLS_CERT", "").(string),
		TLSKey:           envGet("CERT_TELEGRAF_TLS_KEY", "").(string),
		TLSServerName:    envGet("CERT_TELEGRAF_TLS_SERVER_NAME", "").(string),
		UseProxy:         envGet("CERT_TELEGRAF_USE_PROXY", false).(bool),
		ProxyURL:         envGet("CERT_TELEGRAF_PROXY_URL", "").(string),
		Tags:             strings.Split(envStringExpand("CERT_TELEGRAF_TAGS", ""), ","),
	},
}

var discoveryObserviumOptions = discovery.ObserviumOptions{
	Schedule: envGet("OBSERVIUM_SCHEDULE", "").(string),
	ObserviumOptions: vendors.ObserviumOptions{
		Timeout:  envGet("OBSERVIUM_TIMEOUT", 5).(int),
		Insecure: envGet("OBSERVIUM_INSECURE", false).(bool),
		URL:      envGet("OBSERVIUM_URL", "").(string),
		User:     envGet("OBSERVIUM_USER", "").(string),
		Password: envGet("OBSERVIUM_PASSWORD", "").(string),
		Token:    envGet("OBSERVIUM_TOKEN", "").(string),
	},
}

var discoveryPubSubOptions = discovery.PubSubOptions{
	Enabled:                 envGet("PUBSUB_ENABLED", false).(bool),
	Credentials:             envGet("PUBSUB_CREDENTIALS", "").(string),
	ProjectID:               envGet("PUBSUB_PROJECT_ID", "").(string),
	TopicID:                 envGet("PUBSUB_TOPIC", "").(string),
	SubscriptionName:        envGet("PUBSUB_SUBSCRIPTION_NAME", "").(string),
	SubscriptionAckDeadline: envGet("PUBSUB_SUBSCRIPTION_ACK_DEADLINE", 20).(int),
	SubscriptionRetention:   envGet("PUBSUB_SUBSCRIPTION_RETENTION", 86400).(int),
	Dir:                     envGet("PUBSUB_DIR", "").(string),
}

var sinkJsonOptions = sink.JsonOptions{
	Dir: envGet("SINK_JSON_DIR", "").(string),
}

var sinkYamlOptions = sink.YamlOptions{
	Dir: envGet("SINK_YAML_DIR", "").(string),
}

var sinkTelegrafOptions = sink.TelegrafOptions{
	Pass: strings.Split(envStringExpand("SINK_TELEGRAF_PASS", ""), ","),
}

func getOnlyEnv(key string) string {
	value, ok := os.LookupEnv(key)
	if ok {
		return value
	}
	return fmt.Sprintf("$%s", key)
}

func envGet(s string, def interface{}) interface{} {
	return utils.EnvGet(fmt.Sprintf("%s_%s", APPNAME, s), def)
}

func envStringExpand(s string, def string) string {
	snew := envGet(s, def).(string)
	return os.Expand(snew, getOnlyEnv)
}

func envFileContentExpand(s string, def string) string {
	snew := envGet(s, def).(string)
	bytes, err := utils.Content(snew)
	if err != nil {
		return def
	}
	return os.Expand(string(bytes), getOnlyEnv)
}

func interceptSyscall() {

	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-c
		logs.Info("Exiting...")
		os.Exit(1)
	}()
}

func runSchedule(s *gocron.Scheduler, schedule string, jobFun interface{}) {

	arr := strings.Split(schedule, " ")
	if len(arr) == 1 {
		s.Every(schedule).WaitForSchedule().Do(jobFun)
	} else {
		s.Cron(schedule).Do(jobFun)
	}
}

func runStandAloneDiscovery(wg *sync.WaitGroup, discovery common.Discovery, logger *sreCommon.Logs) {

	if reflect.ValueOf(discovery).IsNil() {
		return
	}
	wg.Add(1)
	go func(d common.Discovery) {
		defer wg.Done()
		d.Discover()
	}(discovery)
	logger.Debug("%s: discovery enabled on event", discovery.Name())
}

func runPrometheusDiscovery(wg *sync.WaitGroup, runOnce bool, scheduler *gocron.Scheduler, schedule string, name, value string, discovery common.Discovery, logger *sreCommon.Logs) {

	if reflect.ValueOf(discovery).IsNil() {
		return
	}
	// run once and return if there is flag
	if runOnce {
		wg.Add(1)
		go func(d common.Discovery) {
			defer wg.Done()
			d.Discover()
		}(discovery)
		return
	}
	// run on schedule if there is one defined
	if !utils.IsEmpty(schedule) {
		runSchedule(scheduler, schedule, discovery.Discover)
		logger.Debug("%s: %s discovery enabled on schedule: %s", discovery.Name(), value, schedule)
	}
}

func runSimpleDiscovery(wg *sync.WaitGroup, runOnce bool, scheduler *gocron.Scheduler, schedule string, discovery common.Discovery, logger *sreCommon.Logs) {

	if reflect.ValueOf(discovery).IsNil() {
		return
	}
	// run once and return if there is flag
	if runOnce {
		wg.Add(1)
		go func(d common.Discovery) {
			defer wg.Done()
			d.Discover()
		}(discovery)
		return
	}
	// run on schedule if there is one defined
	if !utils.IsEmpty(schedule) {
		runSchedule(scheduler, schedule, discovery.Discover)
		logger.Debug("%s: discovery enabled on schedule: %s", discovery.Name(), schedule)
	}
}

func Execute() {

	rootCmd := &cobra.Command{
		Use:   "discovery",
		Short: "Discovery",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {

			stdoutOptions.Version = version
			stdout = sreProvider.NewStdout(stdoutOptions)
			if utils.Contains(rootOptions.Logs, "stdout") && stdout != nil {
				stdout.SetCallerOffset(2)
				logs.Register(stdout)
			}

			logs.Info("Booting...")

			// Metrics
			prometheusMetricsOptions.Version = version
			prometheus := sreProvider.NewPrometheusMeter(prometheusMetricsOptions, logs, stdout)
			if utils.Contains(rootOptions.Metrics, "prometheus") && prometheus != nil {
				prometheus.StartInWaitGroup(&mainWG)
				metrics.Register(prometheus)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {

			obs := common.NewObservability(logs, metrics)
			logger := obs.Logs()

			sinks := common.NewSinks(obs)
			sinks.Add(sink.NewJson(sinkJsonOptions, obs))
			sinks.Add(sink.NewYaml(sinkYamlOptions, obs))
			sinks.Add(sink.NewTelegraf(sinkTelegrafOptions, obs))

			// define scheduler
			scheduler := gocron.NewScheduler(time.UTC)
			wg := &sync.WaitGroup{}

			// run prometheus discoveries for each prometheus name for URLs and run related discoveries
			promDiscoveryObjects := common.GetPrometheusDiscoveriesByInstances(discoveryPrometheusOptions.Names)
			for _, prom := range promDiscoveryObjects {

				opts := common.PrometheusOptions{}
				copier.CopyWithOption(&opts, &discoveryPrometheusOptions, copier.Option{IgnoreEmpty: true, DeepCopy: true})

				m := make(map[string]string)
				m["name"] = prom.Name
				m["url"] = prom.URL
				opts.URL = common.Render(discoveryPrometheusOptions.URL, m, obs)
				opts.HttpUsername = prom.HttpUsername
				opts.HttpPassword = prom.HttpPassword

				if utils.IsEmpty(opts.URL) || utils.IsEmpty(prom.Name) {
					logger.Debug("Prometheus discovery is not found")
					continue
				}
				runPrometheusDiscovery(wg, rootOptions.RunOnce, scheduler, discoverySignalOptions.Schedule, prom.Name, prom.URL, discovery.NewSignal(prom.Name, opts, discoverySignalOptions, obs, sinks), logger)
				runPrometheusDiscovery(wg, rootOptions.RunOnce, scheduler, discoveryDNSOptions.Schedule, prom.Name, prom.URL, discovery.NewDNS(prom.Name, opts, discoveryDNSOptions, obs, sinks), logger)
				runPrometheusDiscovery(wg, rootOptions.RunOnce, scheduler, discoveryHTTPOptions.Schedule, prom.Name, prom.URL, discovery.NewHTTP(prom.Name, opts, discoveryHTTPOptions, obs, sinks), logger)
				runPrometheusDiscovery(wg, rootOptions.RunOnce, scheduler, discoveryTCPOptions.Schedule, prom.Name, prom.URL, discovery.NewTCP(prom.Name, opts, discoveryTCPOptions, obs, sinks), logger)
				runPrometheusDiscovery(wg, rootOptions.RunOnce, scheduler, discoveryCertOptions.Schedule, prom.Name, prom.URL, discovery.NewCert(prom.Name, opts, discoveryCertOptions, obs, sinks), logger)
			}
			// run simple discoveries
			runSimpleDiscovery(wg, rootOptions.RunOnce, scheduler, discoveryObserviumOptions.Schedule, discovery.NewObservium(discoveryObserviumOptions, obs, sinks), logger)

			scheduler.StartAsync()

			// run supportive discoveries without scheduler
			if !rootOptions.RunOnce {
				runStandAloneDiscovery(wg, discovery.NewPubSub(discoveryPubSubOptions, obs, sinks), logger)
			}
			wg.Wait()

			// start wait if there are some jobs
			if scheduler.Len() > 0 {
				mainWG.Wait()
			}
		},
	}

	flags := rootCmd.PersistentFlags()

	flags.StringSliceVar(&rootOptions.Logs, "logs", rootOptions.Logs, "Log providers: stdout")
	flags.StringSliceVar(&rootOptions.Metrics, "metrics", rootOptions.Metrics, "Metric providers: prometheus")
	flags.BoolVar(&rootOptions.RunOnce, "run-once", rootOptions.RunOnce, "Run once")

	flags.StringVar(&stdoutOptions.Format, "stdout-format", stdoutOptions.Format, "Stdout format: json, text, template")
	flags.StringVar(&stdoutOptions.Level, "stdout-level", stdoutOptions.Level, "Stdout level: info, warn, error, debug, panic")
	flags.StringVar(&stdoutOptions.Template, "stdout-template", stdoutOptions.Template, "Stdout template")
	flags.StringVar(&stdoutOptions.TimestampFormat, "stdout-timestamp-format", stdoutOptions.TimestampFormat, "Stdout timestamp format")
	flags.BoolVar(&stdoutOptions.TextColors, "stdout-text-colors", stdoutOptions.TextColors, "Stdout text colors")
	flags.BoolVar(&stdoutOptions.Debug, "stdout-debug", stdoutOptions.Debug, "Stdout debug")

	flags.StringVar(&prometheusMetricsOptions.URL, "prometheus-metrics-url", prometheusMetricsOptions.URL, "Prometheus metrics endpoint url")
	flags.StringVar(&prometheusMetricsOptions.Listen, "prometheus-metrics-listen", prometheusMetricsOptions.Listen, "Prometheus metrics listen")
	flags.StringVar(&prometheusMetricsOptions.Prefix, "prometheus-metrics-prefix", prometheusMetricsOptions.Prefix, "Prometheus metrics prefix")

	flags.StringVar(&discoveryPrometheusOptions.Names, "prometheus-names", discoveryPrometheusOptions.Names, "Prometheus discovery names")
	flags.StringVar(&discoveryPrometheusOptions.URL, "prometheus-url", discoveryPrometheusOptions.URL, "Prometheus discovery URL")
	flags.IntVar(&discoveryPrometheusOptions.Timeout, "prometheus-timeout", discoveryPrometheusOptions.Timeout, "Prometheus discovery timeout in seconds")
	flags.BoolVar(&discoveryPrometheusOptions.Insecure, "prometheus-insecure", discoveryPrometheusOptions.Insecure, "Prometheus discovery insecure")

	// Signal
	flags.StringVar(&discoverySignalOptions.Schedule, "signal-schedule", discoverySignalOptions.Schedule, "Signal discovery schedule")
	flags.StringVar(&discoverySignalOptions.Query, "signal-query", discoverySignalOptions.Query, "Signal discovery query")
	flags.StringVar(&discoverySignalOptions.QueryPeriod, "signal-query-period", discoverySignalOptions.QueryPeriod, "Signal discovery query period")
	flags.StringVar(&discoverySignalOptions.QueryStep, "signal-query-step", discoverySignalOptions.QueryStep, "Signal discovery query step")
	flags.StringVar(&discoverySignalOptions.Service, "signal-service", discoverySignalOptions.Service, "Signal discovery service label")
	flags.StringVar(&discoverySignalOptions.Field, "signal-field", discoverySignalOptions.Field, "Signal discovery field label")
	flags.StringVar(&discoverySignalOptions.Metric, "signal-metric", discoverySignalOptions.Metric, "Signal discovery metric label")
	flags.StringVar(&discoverySignalOptions.Files, "signal-files", discoverySignalOptions.Files, "Signal discovery files")
	flags.StringSliceVar(&discoverySignalOptions.Disabled, "signal-disabled", discoverySignalOptions.Disabled, "Signal discovery disabled services")
	flags.StringVar(&discoverySignalOptions.BaseTemplate, "signal-base-template", discoverySignalOptions.BaseTemplate, "Signal discovery base template")
	flags.StringVar(&discoverySignalOptions.Vars, "signal-vars", discoverySignalOptions.Vars, "Signal discovery vars")

	flags.StringVar(&discoverySignalOptions.TelegrafTags, "signal-telegraf-tags", discoverySignalOptions.TelegrafTags, "Signal discovery telegraf tags")
	flags.StringVar(&discoverySignalOptions.TelegrafTemplate, "signal-telegraf-template", discoverySignalOptions.TelegrafTemplate, "Signal discovery telegraf template")
	flags.BoolVar(&discoverySignalOptions.TelegrafChecksum, "signal-telegraf-checksum", discoverySignalOptions.TelegrafChecksum, "Signal discovery telegraf checksum")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.URL, "signal-telegraf-url", discoverySignalOptions.TelegrafOptions.URL, "Signal discovery telegraf URL")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.Version, "signal-telegraf-version", discoverySignalOptions.TelegrafOptions.Version, "Signal discovery telegraf version")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.Params, "signal-telegraf-params", discoverySignalOptions.TelegrafOptions.Params, "Signal discovery telegraf params")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.Interval, "signal-telegraf-interval", discoverySignalOptions.TelegrafOptions.Interval, "Signal discovery telegraf interval")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.Timeout, "signal-telegraf-timeout", discoverySignalOptions.TelegrafOptions.Timeout, "Signal discovery telegraf timeout")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.Duration, "signal-telegraf-duration", discoverySignalOptions.TelegrafOptions.Duration, "Signal discovery telegraf duration")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.Prefix, "signal-telegraf-prefix", discoverySignalOptions.TelegrafOptions.Prefix, "Signal discovery telegraf prefix")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.QualityName, "signal-telegraf-quality-name", discoverySignalOptions.TelegrafOptions.QualityName, "Signal discovery telegraf quality name")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.QualityRange, "signal-telegraf-quality-range", discoverySignalOptions.TelegrafOptions.QualityRange, "Signal discovery telegraf quality range")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.QualityEvery, "signal-telegraf-quality-every", discoverySignalOptions.TelegrafOptions.QualityEvery, "Signal discovery telegraf quality every")
	flags.IntVar(&discoverySignalOptions.TelegrafOptions.QualityPoints, "signal-telegraf-quality-points", discoverySignalOptions.TelegrafOptions.QualityPoints, "Signal discovery telegraf quality points")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.QualityQuery, "signal-telegraf-quality-query", discoverySignalOptions.TelegrafOptions.QualityQuery, "Signal discovery telegraf quality query")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.AvailabilityName, "signal-telegraf-availability-name", discoverySignalOptions.TelegrafOptions.AvailabilityName, "Signal discovery telegraf availability name")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.MetricName, "signal-telegraf-metric-name", discoverySignalOptions.TelegrafOptions.MetricName, "Signal discovery telegraf metric name")
	flags.StringSliceVar(&discoverySignalOptions.TelegrafOptions.DefaultTags, "signal-telegraf-default-tags", discoverySignalOptions.TelegrafOptions.DefaultTags, "Signal discovery telegraf default tags")
	flags.StringVar(&discoverySignalOptions.TelegrafOptions.VarFormat, "signal-telegraf-var-format", discoverySignalOptions.TelegrafOptions.VarFormat, "Signal discovery telegraf var format")

	// DNS
	flags.StringVar(&discoveryDNSOptions.Schedule, "dns-schedule", discoveryDNSOptions.Schedule, "DNS discovery schedule")
	flags.StringVar(&discoveryDNSOptions.Query, "dns-query", discoveryDNSOptions.Query, "DNS discovery query")
	flags.StringVar(&discoveryDNSOptions.QueryPeriod, "dns-query-period", discoveryDNSOptions.QueryPeriod, "DNS discovery query period")
	flags.StringVar(&discoveryDNSOptions.QueryStep, "dns-query-step", discoveryDNSOptions.QueryStep, "DNS discovery query step")
	flags.StringVar(&discoveryDNSOptions.Pattern, "dns-pattern", discoveryDNSOptions.Pattern, "DNS discovery domain pattern")
	flags.StringVar(&discoveryDNSOptions.Names, "dns-names", discoveryDNSOptions.Names, "DNS discovery domain names")
	flags.StringVar(&discoveryDNSOptions.Exclusion, "dns-exclusion", discoveryDNSOptions.Exclusion, "DNS discovery domain exclusion")

	flags.StringVar(&discoveryDNSOptions.TelegrafConf, "dns-telegraf-conf", discoveryDNSOptions.TelegrafConf, "DNS discovery telegraf conf")
	flags.StringVar(&discoveryDNSOptions.TelegrafTemplate, "dns-telegraf-template", discoveryDNSOptions.TelegrafTemplate, "DNS discovery telegraf template")
	flags.BoolVar(&discoveryDNSOptions.TelegrafChecksum, "dns-telegraf-checksum", discoveryDNSOptions.TelegrafChecksum, "DNS discovery telegraf checksum")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.Interval, "dns-telegraf-interval", discoveryDNSOptions.TelegrafOptions.Interval, "DNS discovery telegraf interval")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.Servers, "dns-telegraf-servers", discoveryDNSOptions.TelegrafOptions.Servers, "DNS discovery telegraf servers")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.Network, "dns-telegraf-network", discoveryDNSOptions.TelegrafOptions.Network, "DNS discovery telegraf network")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.Domains, "dns-telegraf-domains", discoveryDNSOptions.TelegrafOptions.Domains, "DNS discovery telegraf domains")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.RecordType, "dns-telegraf-record-type", discoveryDNSOptions.TelegrafOptions.RecordType, "DNS discovery telegraf record type")
	flags.IntVar(&discoveryDNSOptions.TelegrafOptions.Port, "dns-telegraf-port", discoveryDNSOptions.TelegrafOptions.Port, "DNS discovery telegraf port")
	flags.IntVar(&discoveryDNSOptions.TelegrafOptions.Timeout, "dns-telegraf-timeout", discoveryDNSOptions.TelegrafOptions.Timeout, "DNS discovery telegraf timeout")
	flags.StringSliceVar(&discoveryDNSOptions.TelegrafOptions.Tags, "dns-telegraf-tags", discoveryDNSOptions.TelegrafOptions.Tags, "DNS discovery telegraf tags")

	// HTTP
	flags.StringVar(&discoveryHTTPOptions.Schedule, "http-schedule", discoveryHTTPOptions.Schedule, "HTTP discovery schedule")
	flags.StringVar(&discoveryHTTPOptions.Query, "http-query", discoveryHTTPOptions.Query, "HTTP discovery query")
	flags.StringVar(&discoveryHTTPOptions.QueryPeriod, "http-query-period", discoveryHTTPOptions.QueryPeriod, "HTTP discovery query period")
	flags.StringVar(&discoveryHTTPOptions.QueryStep, "http-query-step", discoveryHTTPOptions.QueryStep, "HTTP discovery query step")
	flags.StringVar(&discoveryHTTPOptions.Pattern, "http-pattern", discoveryHTTPOptions.Pattern, "HTTP discovery pattern")
	flags.StringVar(&discoveryHTTPOptions.Names, "http-names", discoveryHTTPOptions.Names, "HTTP discovery names")
	flags.StringVar(&discoveryHTTPOptions.Exclusion, "http-exclusion", discoveryHTTPOptions.Exclusion, "HTTP discovery exclusion")
	flags.StringVar(&discoveryHTTPOptions.NoSSL, "http-no-ssl", discoveryHTTPOptions.NoSSL, "HTTP no SSL pattern")

	flags.StringVar(&discoveryHTTPOptions.TelegrafConf, "http-telegraf-conf", discoveryHTTPOptions.TelegrafConf, "HTTP discovery telegraf conf")
	flags.StringVar(&discoveryHTTPOptions.TelegrafTemplate, "http-telegraf-template", discoveryHTTPOptions.TelegrafTemplate, "HTTP discovery telegraf template")
	flags.BoolVar(&discoveryHTTPOptions.TelegrafChecksum, "http-telegraf-checksum", discoveryHTTPOptions.TelegrafChecksum, "HTTP discovery telegraf checksum")
	flags.StringVar(&discoveryHTTPOptions.TelegrafOptions.Interval, "http-telegraf-interval", discoveryHTTPOptions.TelegrafOptions.Interval, "HTTP discovery telegraf interval")
	flags.StringVar(&discoveryHTTPOptions.TelegrafOptions.URLs, "http-telegraf-urls", discoveryHTTPOptions.TelegrafOptions.URLs, "HTTP discovery telegraf URLs")
	flags.StringVar(&discoveryHTTPOptions.TelegrafOptions.Path, "http-telegraf-path", discoveryHTTPOptions.TelegrafOptions.Path, "HTTP discovery telegraf path")
	flags.StringVar(&discoveryHTTPOptions.TelegrafOptions.Method, "http-telegraf-method", discoveryHTTPOptions.TelegrafOptions.Method, "HTTP discovery telegraf method")
	flags.BoolVar(&discoveryHTTPOptions.TelegrafOptions.FollowRedirects, "http-telegraf-follow-redirects", discoveryHTTPOptions.TelegrafOptions.FollowRedirects, "HTTP discovery telegraf follow redirects")
	flags.StringVar(&discoveryHTTPOptions.TelegrafOptions.StringMatch, "http-telegraf-string-match", discoveryHTTPOptions.TelegrafOptions.StringMatch, "HTTP discovery telegraf string match")
	flags.IntVar(&discoveryHTTPOptions.TelegrafOptions.StatusCode, "http-telegraf-status-code", discoveryHTTPOptions.TelegrafOptions.StatusCode, "HTTP discovery telegraf status code")
	flags.StringVar(&discoveryHTTPOptions.TelegrafOptions.Timeout, "http-telegraf-timeout", discoveryHTTPOptions.TelegrafOptions.Timeout, "HTTP discovery telegraf timeout")
	flags.StringSliceVar(&discoveryHTTPOptions.TelegrafOptions.Tags, "http-telegraf-tags", discoveryHTTPOptions.TelegrafOptions.Tags, "HTTP discovery telegraf tags")

	// TCP
	flags.StringVar(&discoveryTCPOptions.Schedule, "tcp-schedule", discoveryTCPOptions.Schedule, "TCP discovery schedule")
	flags.StringVar(&discoveryTCPOptions.Query, "tcp-query", discoveryTCPOptions.Query, "TCP discovery query")
	flags.StringVar(&discoveryTCPOptions.QueryPeriod, "tcp-query-period", discoveryTCPOptions.QueryPeriod, "TCP discovery query period")
	flags.StringVar(&discoveryTCPOptions.QueryStep, "tcp-query-step", discoveryTCPOptions.QueryStep, "TCP discovery query step")
	flags.StringVar(&discoveryTCPOptions.Pattern, "tcp-pattern", discoveryTCPOptions.Pattern, "TCP discovery pattern")
	flags.StringVar(&discoveryTCPOptions.Names, "tcp-names", discoveryTCPOptions.Names, "TCP discovery names")
	flags.StringVar(&discoveryTCPOptions.Exclusion, "tcp-exclusion", discoveryTCPOptions.Exclusion, "TCP discovery exclusion")

	flags.StringVar(&discoveryTCPOptions.TelegrafConf, "tcp-telegraf-conf", discoveryTCPOptions.TelegrafConf, "TCP discovery telegraf conf")
	flags.StringVar(&discoveryTCPOptions.TelegrafTemplate, "tcp-telegraf-template", discoveryTCPOptions.TelegrafTemplate, "TCP discovery telegraf template")
	flags.BoolVar(&discoveryTCPOptions.TelegrafChecksum, "tcp-telegraf-checksum", discoveryTCPOptions.TelegrafChecksum, "TCP discovery telegraf checksum")
	flags.StringVar(&discoveryTCPOptions.TelegrafOptions.Interval, "tcp-telegraf-interval", discoveryTCPOptions.TelegrafOptions.Interval, "TCP discovery telegraf interval")
	flags.StringVar(&discoveryTCPOptions.TelegrafOptions.Send, "tcp-telegraf-send", discoveryTCPOptions.TelegrafOptions.Send, "TCP discovery telegraf send")
	flags.StringVar(&discoveryTCPOptions.TelegrafOptions.Expect, "tcp-telegraf-expect", discoveryTCPOptions.TelegrafOptions.Expect, "TCP discovery telegraf expect")
	flags.StringVar(&discoveryTCPOptions.TelegrafOptions.Timeout, "tcp-telegraf-timeout", discoveryTCPOptions.TelegrafOptions.Timeout, "TCP discovery telegraf timeout")
	flags.StringVar(&discoveryTCPOptions.TelegrafOptions.ReadTimeout, "tcp-telegraf-read-timeout", discoveryTCPOptions.TelegrafOptions.ReadTimeout, "TCP discovery telegraf read timeout")
	flags.StringSliceVar(&discoveryTCPOptions.TelegrafOptions.Tags, "tcp-telegraf-tags", discoveryTCPOptions.TelegrafOptions.Tags, "TCP discovery telegraf tags")

	// CERT
	flags.StringVar(&discoveryCertOptions.Schedule, "cert-schedule", discoveryCertOptions.Schedule, "Cert discovery schedule")
	flags.StringVar(&discoveryCertOptions.Query, "cert-query", discoveryCertOptions.Query, "Cert discovery query")
	flags.StringVar(&discoveryCertOptions.QueryPeriod, "cert-query-period", discoveryCertOptions.QueryPeriod, "Cert discovery query period")
	flags.StringVar(&discoveryCertOptions.QueryStep, "cert-query-step", discoveryCertOptions.QueryStep, "Cert discovery query step")
	flags.StringVar(&discoveryCertOptions.Pattern, "cert-pattern", discoveryCertOptions.Pattern, "Cert discovery pattern")
	flags.StringVar(&discoveryCertOptions.Names, "cert-names", discoveryCertOptions.Names, "Cert discovery names")
	flags.StringVar(&discoveryCertOptions.Exclusion, "cert-exclusion", discoveryCertOptions.Exclusion, "Cert discovery exclusion")

	flags.StringVar(&discoveryCertOptions.TelegrafConf, "cert-telegraf-conf", discoveryCertOptions.TelegrafConf, "Cert discovery telegraf conf")
	flags.StringVar(&discoveryCertOptions.TelegrafTemplate, "cert-telegraf-template", discoveryCertOptions.TelegrafTemplate, "Cert discovery telegraf template")
	flags.BoolVar(&discoveryCertOptions.TelegrafChecksum, "cert-telegraf-checksum", discoveryCertOptions.TelegrafChecksum, "Cert discovery telegraf checksum")
	flags.StringVar(&discoveryCertOptions.TelegrafOptions.Interval, "cert-telegraf-interval", discoveryCertOptions.TelegrafOptions.Interval, "Cert discovery telegraf interval")
	flags.StringVar(&discoveryCertOptions.TelegrafOptions.Timeout, "cert-telegraf-timeout", discoveryCertOptions.TelegrafOptions.Timeout, "Cert discovery telegraf timeout")
	flags.StringVar(&discoveryCertOptions.TelegrafOptions.ServerName, "cert-telegraf-server-name", discoveryCertOptions.TelegrafOptions.ServerName, "Cert discovery telegraf server name")
	flags.BoolVar(&discoveryCertOptions.TelegrafOptions.ExcludeRootCerts, "cert-telegraf-exclude-root-certs", discoveryCertOptions.TelegrafOptions.ExcludeRootCerts, "Cert discovery telegraf exclude root certs")
	flags.StringVar(&discoveryCertOptions.TelegrafOptions.TLSCA, "cert-telegraf-read-tls-ca", discoveryCertOptions.TelegrafOptions.TLSCA, "Cert discovery telegraf TLS CA")
	flags.StringVar(&discoveryCertOptions.TelegrafOptions.TLSCert, "cert-telegraf-read-tls-cert", discoveryCertOptions.TelegrafOptions.TLSCert, "Cert discovery telegraf TLS cert")
	flags.StringVar(&discoveryCertOptions.TelegrafOptions.TLSServerName, "cert-telegraf-read-tls-server-name", discoveryCertOptions.TelegrafOptions.TLSServerName, "Cert discovery telegraf TLS server name")
	flags.BoolVar(&discoveryCertOptions.TelegrafOptions.UseProxy, "cert-telegraf-use-proxy", discoveryCertOptions.TelegrafOptions.UseProxy, "Cert discovery telegraf use proxy")
	flags.StringVar(&discoveryCertOptions.TelegrafOptions.ProxyURL, "cert-telegraf-read-proxy-url", discoveryCertOptions.TelegrafOptions.ProxyURL, "Cert discovery telegraf proxy URL")
	flags.StringSliceVar(&discoveryCertOptions.TelegrafOptions.Tags, "cert-telegraf-tags", discoveryCertOptions.TelegrafOptions.Tags, "Cert discovery telegraf tags")

	// Observium
	flags.StringVar(&discoveryObserviumOptions.Schedule, "observium-schedule", discoveryObserviumOptions.Schedule, "Observium discovery schedule")
	flags.IntVar(&discoveryObserviumOptions.Timeout, "observium-timeout", discoveryObserviumOptions.Timeout, "Observium discovery timeout")
	flags.BoolVar(&discoveryObserviumOptions.Insecure, "observium-insecure", discoveryObserviumOptions.Insecure, "Observium discovery insecure")
	flags.StringVar(&discoveryObserviumOptions.URL, "observium-url", discoveryObserviumOptions.URL, "Observium discovery URL")
	flags.StringVar(&discoveryObserviumOptions.User, "observium-user", discoveryObserviumOptions.User, "Observium discovery user")
	flags.StringVar(&discoveryObserviumOptions.Password, "observium-password", discoveryObserviumOptions.Password, "Observium discovery password")
	flags.StringVar(&discoveryObserviumOptions.Token, "observium-token", discoveryObserviumOptions.Token, "Observium discovery token")

	// PubSub
	flags.BoolVar(&discoveryPubSubOptions.Enabled, "pubsub-enabled", discoveryPubSubOptions.Enabled, "PaubSub enable pulling from the PubSub topic")
	flags.StringVar(&discoveryPubSubOptions.Credentials, "pubsub-credentials", discoveryPubSubOptions.Credentials, "Credentials for PubSub")
	flags.StringVar(&discoveryPubSubOptions.ProjectID, "pubsub-project-id", discoveryPubSubOptions.ProjectID, "PubSub project ID")
	flags.StringVar(&discoveryPubSubOptions.TopicID, "pubsub-topic-id", discoveryPubSubOptions.TopicID, "PubSub topic ID")
	flags.StringVar(&discoveryPubSubOptions.SubscriptionName, "pubsub-subscription-name", discoveryPubSubOptions.SubscriptionName, "PubSub subscription name")
	flags.IntVar(&discoveryPubSubOptions.SubscriptionAckDeadline, "pubsub-subscription-ack-deadline", discoveryPubSubOptions.SubscriptionAckDeadline, "PubSub subscription ack deadline duration seconds")
	flags.IntVar(&discoveryPubSubOptions.SubscriptionRetention, "pubsub-subscription-retention", discoveryPubSubOptions.SubscriptionRetention, "PubSub subscription retention duration seconds")
	flags.StringVar(&discoveryPubSubOptions.Dir, "pubsub-dir", discoveryPubSubOptions.Dir, "Pubsub directory")

	// Sink Json
	flags.StringVar(&sinkJsonOptions.Dir, "sink-json-dir", sinkJsonOptions.Dir, "Sink json directory")

	// Sink Yaml
	flags.StringVar(&sinkYamlOptions.Dir, "sink-yaml-dir", sinkYamlOptions.Dir, "Sink yaml directory")

	// Sink Telegraf
	flags.StringSliceVar(&sinkTelegrafOptions.Pass, "sink-telegraf-pass", sinkTelegrafOptions.Pass, "Telegraf pass through")

	interceptSyscall()

	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print the version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		logs.Error(err)
		os.Exit(1)
	}
}
