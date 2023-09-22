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
	"github.com/devopsext/discovery/telegraf"
	sreCommon "github.com/devopsext/sre/common"
	sreProvider "github.com/devopsext/sre/provider"
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

	TelegrafOptions: telegraf.InputPrometheusHttpConfigOptions{
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
	Schedule:      envGet("DNS_SCHEDULE", "").(string),
	Query:         envFileContentExpand("DNS_QUERY", ""),
	QueryPeriod:   envGet("DNS_QUERY_PERIOD", "").(string),
	QueryStep:     envGet("DNS_QUERY_STEP", "").(string),
	DomainPattern: envGet("DNS_DOMAIN_PATTERN", "").(string),
	DomainNames:   envFileContentExpand("DNS_DOMAIN_NAMES", ""),

	TelegrafConf:     envGet("DNS_TELEGRAF_CONF", "").(string),
	TelegrafTemplate: envFileContentExpand("DNS_TELEGRAF_TEMPLATE", ""),
	TelegrafChecksum: envGet("DNS_TELEGRAF_CHECKSUM", false).(bool),

	TelegrafOptions: telegraf.InputDNSQueryConfigOptions{
		Interval:   envGet("DNS_TELEGRAF_INTERVAL", "10s").(string),
		Servers:    envGet("DNS_TELEGRAF_SERVERS", "").(string),
		Network:    envGet("DNS_TELEGRAF_NETWORK", "upd").(string),
		RecordType: envGet("DNS_TELEGRAF_RECORD_TYPE", "A").(string),
		Port:       envGet("DNS_TELEGRAF_PORT", 53).(int),
		Tags:       strings.Split(envStringExpand("DNS_TELEGRAF_TAGS", ""), ","),
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
		s.Every(schedule).Do(jobFun)
	} else {
		s.Cron(schedule).Do(jobFun)
	}
}

func runStandAloneDiscovery(wg *sync.WaitGroup, runOnce bool, typ string, discovery common.Discovery, logger *sreCommon.Logs) {

	if reflect.ValueOf(discovery).IsNil() {
		logger.Debug("%s: discovery disabled", typ)
		return
	}
	// run once and return if there is flag
	if runOnce {
		wg.Add(1)
		go func(d common.Discovery) {
			defer wg.Done()
			d.Discover()
		}(discovery)
	}
}

func runPrometheusDiscovery(wg *sync.WaitGroup, runOnce bool, scheduler *gocron.Scheduler, schedule string, typ, name, value string, discovery common.Discovery, logger *sreCommon.Logs) {

	if reflect.ValueOf(discovery).IsNil() {
		logger.Debug("%s: discovery disabled for %s", typ, name)
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
		logger.Debug("%s: %s discovery enabled on schedule: %s", typ, value, schedule)
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

			observability := common.NewObservability(logs, metrics)
			logger := observability.Logs()
			wg := &sync.WaitGroup{}
			scheduler := gocron.NewScheduler(time.UTC)

			// use each prometheus name for URLs and run related discoveries
			proms := common.GetPrometheusDiscoveriesByInstances(discoveryPrometheusOptions.Names)
			for k, v := range proms {

				opts := common.PrometheusOptions{}
				copier.CopyWithOption(&opts, &discoveryPrometheusOptions, copier.Option{IgnoreEmpty: true, DeepCopy: true})

				m := make(map[string]string)
				m["name"] = k
				m["url"] = v
				opts.URL = common.Render(discoveryPrometheusOptions.URL, m, observability)

				if utils.IsEmpty(opts.URL) || utils.IsEmpty(k) {
					logger.Debug("Prometheus discovery is not found")
					continue
				}
				runPrometheusDiscovery(wg, rootOptions.RunOnce, scheduler, discoverySignalOptions.Schedule, "Signal", k, v, discovery.NewSignal(k, opts, discoverySignalOptions, observability), logger)
				runPrometheusDiscovery(wg, rootOptions.RunOnce, scheduler, discoveryDNSOptions.Schedule, "DNS", k, v, discovery.NewDNS(k, opts, discoveryDNSOptions, observability), logger)
			}

			// run supportive discoveries without scheduler
			if !rootOptions.RunOnce {
				runStandAloneDiscovery(wg, true, "PubSub", discovery.NewPubSub(discoveryPubSubOptions, observability), logger)
			}

			wg.Wait()
			scheduler.StartAsync()

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
	flags.StringVar(&discoveryDNSOptions.DomainPattern, "dns-domain-pattern", discoveryDNSOptions.DomainPattern, "DNS discovery domain pattern")
	flags.StringVar(&discoveryDNSOptions.DomainNames, "dns-domain-names", discoveryDNSOptions.DomainNames, "DNS discovery domain names")

	flags.StringVar(&discoveryDNSOptions.TelegrafConf, "dns-telegraf-conf", discoveryDNSOptions.TelegrafConf, "DNS discovery telegraf conf")
	flags.StringVar(&discoveryDNSOptions.TelegrafTemplate, "dns-telegraf-template", discoveryDNSOptions.TelegrafTemplate, "DNS discovery telegraf template")
	flags.BoolVar(&discoveryDNSOptions.TelegrafChecksum, "dns-telegraf-checksum", discoveryDNSOptions.TelegrafChecksum, "DNS discovery telegraf checksum")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.Interval, "dns-telegraf-interval", discoveryDNSOptions.TelegrafOptions.Interval, "DNS discovery telegraf interval")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.Servers, "dns-telegraf-servers", discoveryDNSOptions.TelegrafOptions.Servers, "DNS discovery telegraf servers")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.Network, "dns-telegraf-network", discoveryDNSOptions.TelegrafOptions.Network, "DNS discovery telegraf network")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.Domains, "dns-telegraf-domains", discoveryDNSOptions.TelegrafOptions.Domains, "DNS discovery telegraf domains")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.RecordType, "dns-telegraf-record-type", discoveryDNSOptions.TelegrafOptions.RecordType, "DNS discovery telegraf record type")
	flags.IntVar(&discoveryDNSOptions.TelegrafOptions.Port, "dns-telegraf-port", discoveryDNSOptions.TelegrafOptions.Port, "DNS discovery telegraf port")
	flags.StringVar(&discoveryDNSOptions.TelegrafOptions.Timeout, "dns-telegraf-timeout", discoveryDNSOptions.TelegrafOptions.Timeout, "DNS discovery telegraf timeout")
	flags.StringSliceVar(&discoveryDNSOptions.TelegrafOptions.Tags, "dns-telegraf-tags", discoveryDNSOptions.TelegrafOptions.Tags, "DNS discovery telegraf tags")

	// PubSub
	flags.BoolVar(&discoveryPubSubOptions.Enabled, "pubsub-enabled", discoveryPubSubOptions.Enabled, "PaubSub enable pulling from the PubSub topic")
	flags.StringVar(&discoveryPubSubOptions.Credentials, "pubsub-credentials", discoveryPubSubOptions.Credentials, "Credentials for PubSub")
	flags.StringVar(&discoveryPubSubOptions.ProjectID, "pubsub-project-id", discoveryPubSubOptions.ProjectID, "PubSub project ID")
	flags.StringVar(&discoveryPubSubOptions.TopicID, "pubsub-topic-id", discoveryPubSubOptions.TopicID, "PubSub topic ID")
	flags.StringVar(&discoveryPubSubOptions.SubscriptionName, "pubsub-subscription-name", discoveryPubSubOptions.SubscriptionName, "PubSub subscription name")
	flags.IntVar(&discoveryPubSubOptions.SubscriptionAckDeadline, "pubsub-subscription-ack-deadline", discoveryPubSubOptions.SubscriptionAckDeadline, "PubSub subscription ack deadline duration seconds")
	flags.IntVar(&discoveryPubSubOptions.SubscriptionRetention, "pubsub-subscription-retention", discoveryPubSubOptions.SubscriptionRetention, "PubSub subscription retention duration seconds")
	flags.StringVar(&discoveryPubSubOptions.Dir, "pubsub-dir", discoveryPubSubOptions.Dir, "Pubsub directory")

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
