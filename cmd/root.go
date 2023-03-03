package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"sync"
	"syscall"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/vendors"
	sreCommon "github.com/devopsext/sre/common"
	sreProvider "github.com/devopsext/sre/provider"
	"github.com/devopsext/utils"
	"github.com/go-co-op/gocron"
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
}

var rootOptions = RootOptions{
	Logs:    strings.Split(envGet("LOGS", "stdout").(string), ","),
	Metrics: strings.Split(envGet("METRICS", "prometheus").(string), ","),
}

var stdoutOptions = sreProvider.StdoutOptions{
	Format:          envGet("STDOUT_FORMAT", "text").(string),
	Level:           envGet("STDOUT_LEVEL", "info").(string),
	Template:        envGet("STDOUT_TEMPLATE", "{{.file}} {{.msg}}").(string),
	TimestampFormat: envGet("STDOUT_TIMESTAMP_FORMAT", time.RFC3339Nano).(string),
	TextColors:      envGet("STDOUT_TEXT_COLORS", true).(bool),
}

var prometheusOptions = sreProvider.PrometheusOptions{
	URL:    envGet("PROMETHEUS_URL", "/metrics").(string),
	Listen: envGet("PROMETHEUS_LISTEN", "127.0.0.1:8080").(string),
	Prefix: envGet("PROMETHEUS_PREFIX", "events").(string),
}

var prometheusDiscoveryOptions = vendors.PrometheusDiscoveryOptions{
	URL:          envGet("PROMETHEUS_DISCOVERY_URL", "").(string),
	Timeout:      envGet("PROMETHEUS_DISCOVERY_TIMEOUT", 30).(int),
	Insecure:     envGet("PROMETHEUS_DISCOVERY_INSECURE", false).(bool),
	Query:        envGet("PROMETHEUS_DISCOVERY_QUERY", "").(string),
	Metric:       envGet("PROMETHEUS_DISCOVERY_METRIC", "").(string),
	Service:      envGet("PROMETHEUS_DISCOVERY_SERVICE", "").(string),
	Schedule:     envGet("PROMETHEUS_DISCOVERY_SCHEDULE", "").(string),
	Labels:       envGet("PROMETHEUS_DISCOVERY_LABELS", "").(string),
	BaseTemplate: envGet("PROMETHEUS_DISCOVERY_BASE_TEMPLATE", "").(string),

	TelegrafTemplate: envGet("PROMETHEUS_DISCOVERY_TELEGRAF_TEMPLATE", "").(string),
	TelegrafChecksum: envGet("PROMETHEUS_DISCOVERY_TELEGRAF_CHECKSUM", false).(bool),
	TelegrafOptions: common.TelegrafConfigOptions{
		URL:              envGet("PROMETHEUS_DISCOVERY_TELEGRAF_URL", "").(string),
		Version:          envGet("PROMETHEUS_DISCOVERY_TELEGRAF_VERSION", "v1").(string),
		Params:           envGet("PROMETHEUS_DISCOVERY_TELEGRAF_PARAMS", "").(string),
		Interval:         envGet("PROMETHEUS_DISCOVERY_TELEGRAF_INTERVAL", "10s").(string),
		Duration:         envGet("PROMETHEUS_DISCOVERY_TELEGRAF_DURATION", "").(string),
		Timeout:          envGet("PROMETHEUS_DISCOVERY_TELEGRAF_TIMEOUT", "5s").(string),
		Prefix:           envGet("PROMETHEUS_DISCOVERY_TELEGRAF_PREFIX", "").(string),
		QualityName:      envGet("PROMETHEUS_DISCOVERY_TELEGRAF_QUALITY_NAME", "quality").(string),
		QualityRange:     envGet("PROMETHEUS_DISCOVERY_TELEGRAF_QUALITY_RANGE", "5m").(string),
		QualityEvery:     envGet("PROMETHEUS_DISCOVERY_TELEGRAF_QUALITY_EVERY", "15s").(string),
		QualityPoints:    envGet("PROMETHEUS_DISCOVERY_TELEGRAF_QUALITY_POINTS", 20).(int),
		QualityQuery:     envGet("PROMETHEUS_DISCOVERY_TELEGRAF_QUALITY_QUERY", "").(string),
		AvailbailityName: envGet("PROMETHEUS_DISCOVERY_TELEGRAF_AVAILABILITY_NAME", "availability").(string),
		MetricName:       envGet("PROMETHEUS_DISCOVERY_TELEGRAF_METRIC_NAME", "metric").(string),
		DefaultTags:      strings.Split(envGet("PROMETHEUS_DISCOVERY_TELEGRAF_DEFAULT_TAGS", "").(string), ","),
	},
}

func envGet(s string, d interface{}) interface{} {
	return utils.EnvGet(fmt.Sprintf("%s_%s", APPNAME, s), d)
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

func schedule(s *gocron.Scheduler, schedule string, jobFun interface{}) {

	arr := strings.Split(schedule, " ")
	if len(arr) == 1 {
		s.Every(schedule).Do(jobFun)
	} else {
		s.Cron(schedule).Do(jobFun)
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

			prometheusOptions.Version = version
			prometheus := sreProvider.NewPrometheusMeter(prometheusOptions, logs, stdout)
			if utils.Contains(rootOptions.Metrics, "prometheus") && prometheus != nil {
				prometheus.StartInWaitGroup(&mainWG)
				metrics.Register(prometheus)
			}

		},
		Run: func(cmd *cobra.Command, args []string) {

			observability := common.NewObservability(logs, metrics)
			logger := observability.Logs()

			s := gocron.NewScheduler(time.UTC)
			var prometheus *vendors.PrometheusDiscovery
			if !utils.IsEmpty(prometheusDiscoveryOptions.Schedule) {
				prometheus = vendors.NewPrometheusDiscovery(prometheusDiscoveryOptions, observability)
				if prometheus != nil {
					schedule(s, prometheusDiscoveryOptions.Schedule, prometheus.Discover)
					logger.Debug("Prometheus discovery enabled on schedule: %s", prometheusDiscoveryOptions.Schedule)
				}
			}

			if prometheus == nil {
				logger.Debug("Prometheus discovery disabled")
			}
			s.StartAsync()
			mainWG.Wait()
		},
	}

	flags := rootCmd.PersistentFlags()

	flags.StringSliceVar(&rootOptions.Logs, "logs", rootOptions.Logs, "Log providers: stdout")
	flags.StringSliceVar(&rootOptions.Metrics, "metrics", rootOptions.Metrics, "Metric providers: prometheus")

	flags.StringVar(&stdoutOptions.Format, "stdout-format", stdoutOptions.Format, "Stdout format: json, text, template")
	flags.StringVar(&stdoutOptions.Level, "stdout-level", stdoutOptions.Level, "Stdout level: info, warn, error, debug, panic")
	flags.StringVar(&stdoutOptions.Template, "stdout-template", stdoutOptions.Template, "Stdout template")
	flags.StringVar(&stdoutOptions.TimestampFormat, "stdout-timestamp-format", stdoutOptions.TimestampFormat, "Stdout timestamp format")
	flags.BoolVar(&stdoutOptions.TextColors, "stdout-text-colors", stdoutOptions.TextColors, "Stdout text colors")
	flags.BoolVar(&stdoutOptions.Debug, "stdout-debug", stdoutOptions.Debug, "Stdout debug")

	flags.StringVar(&prometheusOptions.URL, "prometheus-url", prometheusOptions.URL, "Prometheus endpoint url")
	flags.StringVar(&prometheusOptions.Listen, "prometheus-listen", prometheusOptions.Listen, "Prometheus listen")
	flags.StringVar(&prometheusOptions.Prefix, "prometheus-prefix", prometheusOptions.Prefix, "Prometheus prefix")

	flags.StringVar(&prometheusDiscoveryOptions.URL, "prometheus-discovery-url", prometheusDiscoveryOptions.URL, "Prometheus discovery URL")
	flags.IntVar(&prometheusDiscoveryOptions.Timeout, "prometheus-discovery-timeout", prometheusDiscoveryOptions.Timeout, "Prometheus discovery timeout in seconds")
	flags.BoolVar(&prometheusDiscoveryOptions.Insecure, "prometheus-discovery-insecure", prometheusDiscoveryOptions.Insecure, "Prometheus discovery insecure")
	flags.StringVar(&prometheusDiscoveryOptions.Query, "prometheus-discovery-query", prometheusDiscoveryOptions.Query, "Prometheus discovery query")
	flags.StringVar(&prometheusDiscoveryOptions.Service, "prometheus-discovery-service", prometheusDiscoveryOptions.Service, "Prometheus discovery service label")
	flags.StringVar(&prometheusDiscoveryOptions.Metric, "prometheus-discovery-metric", prometheusDiscoveryOptions.Metric, "Prometheus discovery metric label")
	flags.StringVar(&prometheusDiscoveryOptions.Schedule, "prometheus-discovery-schedule", prometheusDiscoveryOptions.Schedule, "Prometheus discovery schedule")
	flags.StringVar(&prometheusDiscoveryOptions.BaseTemplate, "prometheus-discovery-base-template", prometheusDiscoveryOptions.BaseTemplate, "Prometheus discovery base template")
	flags.StringVar(&prometheusDiscoveryOptions.Labels, "prometheus-discovery-labels", prometheusDiscoveryOptions.Labels, "Prometheus discovery labels")

	flags.StringVar(&prometheusDiscoveryOptions.TelegrafTemplate, "prometheus-discovery-telegraf-template", prometheusDiscoveryOptions.TelegrafTemplate, "Prometheus discovery telegraf template")
	flags.BoolVar(&prometheusDiscoveryOptions.TelegrafChecksum, "prometheus-discovery-telegraf-checksum", prometheusDiscoveryOptions.TelegrafChecksum, "Prometheus discovery telegraf checksum")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.URL, "prometheus-discovery-telegraf-url", prometheusDiscoveryOptions.TelegrafOptions.URL, "Prometheus discovery telegraf URL")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Version, "prometheus-discovery-telegraf-version", prometheusDiscoveryOptions.TelegrafOptions.Version, "Prometheus discovery telegraf version")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Params, "prometheus-discovery-telegraf-params", prometheusDiscoveryOptions.TelegrafOptions.Params, "Prometheus discovery telegraf params")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Interval, "prometheus-discovery-telegraf-interval", prometheusDiscoveryOptions.TelegrafOptions.Interval, "Prometheus discovery telegraf interval")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Timeout, "prometheus-discovery-telegraf-timeout", prometheusDiscoveryOptions.TelegrafOptions.Timeout, "Prometheus discovery telegraf timeout")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Duration, "prometheus-discovery-telegraf-duration", prometheusDiscoveryOptions.TelegrafOptions.Duration, "Prometheus discovery telegraf duration")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Prefix, "prometheus-discovery-telegraf-prefix", prometheusDiscoveryOptions.TelegrafOptions.Prefix, "Prometheus discovery telegraf prefix")

	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.QualityName, "prometheus-discovery-telegraf-quality-name", prometheusDiscoveryOptions.TelegrafOptions.QualityName, "Prometheus discovery telegraf quality name")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.QualityRange, "prometheus-discovery-telegraf-quality-range", prometheusDiscoveryOptions.TelegrafOptions.QualityRange, "Prometheus discovery telegraf quality range")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.QualityEvery, "prometheus-discovery-telegraf-quality-every", prometheusDiscoveryOptions.TelegrafOptions.QualityEvery, "Prometheus discovery telegraf quality every")
	flags.IntVar(&prometheusDiscoveryOptions.TelegrafOptions.QualityPoints, "prometheus-discovery-telegraf-quality-points", prometheusDiscoveryOptions.TelegrafOptions.QualityPoints, "Prometheus discovery telegraf quality points")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.QualityQuery, "prometheus-discovery-telegraf-quality-query", prometheusDiscoveryOptions.TelegrafOptions.QualityQuery, "Prometheus discovery telegraf quality query")

	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.AvailbailityName, "prometheus-discovery-telegraf-availability-name", prometheusDiscoveryOptions.TelegrafOptions.AvailbailityName, "Prometheus discovery telegraf availability name")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.MetricName, "prometheus-discovery-telegraf-metric-name", prometheusDiscoveryOptions.TelegrafOptions.MetricName, "Prometheus discovery telegraf metric name")
	flags.StringSliceVar(&prometheusDiscoveryOptions.TelegrafOptions.DefaultTags, "prometheus-discovery-telegraf-default-tags", prometheusDiscoveryOptions.TelegrafOptions.DefaultTags, "Prometheus discovery telegraf default tags")

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
