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

var prometheusMetricsOptions = sreProvider.PrometheusOptions{
	URL:    envGet("PROMETHEUS_METRICS_URL", "/metrics").(string),
	Listen: envGet("PROMETHEUS_METRICS_LISTEN", ":8080").(string),
	Prefix: envGet("PROMETHEUS_METRICS_PREFIX", "events").(string),
}

var prometheusDiscoveryOptions = vendors.PrometheusDiscoveryOptions{
	URL:          envStringExpand("PROMETHEUS_URL", ""),
	Timeout:      envGet("PROMETHEUS_TIMEOUT", 30).(int),
	Insecure:     envGet("PROMETHEUS_INSECURE", false).(bool),
	Query:        envFileContentExpand("PROMETHEUS_QUERY", ""),
	QueryPeriod:  envGet("PROMETHEUS_QUERY_PERIOD", "").(string),
	QueryStep:    envGet("PROMETHEUS_QUERY_STEP", "").(string),
	Metric:       envGet("PROMETHEUS_METRIC", "").(string),
	Service:      envGet("PROMETHEUS_SERVICE", "").(string),
	Schedule:     envGet("PROMETHEUS_SCHEDULE", "").(string),
	Vars:         envFileContentExpand("PROMETHEUS_VARS", ""),
	BaseTemplate: envStringExpand("PROMETHEUS_BASE_TEMPLATE", ""),

	TelegrafLabels:   envFileContentExpand("PROMETHEUS_TELEGRAF_LABELS", ""),
	TelegrafTemplate: envStringExpand("PROMETHEUS_TELEGRAF_TEMPLATE", ""),
	TelegrafChecksum: envGet("PROMETHEUS_TELEGRAF_CHECKSUM", false).(bool),
	TelegrafOptions: common.TelegrafConfigOptions{
		URL:              envStringExpand("PROMETHEUS_TELEGRAF_URL", ""),
		Version:          envGet("PROMETHEUS_TELEGRAF_VERSION", "v1").(string),
		Params:           envGet("PROMETHEUS_TELEGRAF_PARAMS", "").(string),
		Interval:         envGet("PROMETHEUS_TELEGRAF_INTERVAL", "10s").(string),
		Duration:         envGet("PROMETHEUS_TELEGRAF_DURATION", "").(string),
		Timeout:          envGet("PROMETHEUS_TELEGRAF_TIMEOUT", "5s").(string),
		Prefix:           envGet("PROMETHEUS_TELEGRAF_PREFIX", "").(string),
		QualityName:      envGet("PROMETHEUS_TELEGRAF_QUALITY_NAME", "quality").(string),
		QualityRange:     envGet("PROMETHEUS_TELEGRAF_QUALITY_RANGE", "5m").(string),
		QualityEvery:     envGet("PROMETHEUS_TELEGRAF_QUALITY_EVERY", "15s").(string),
		QualityPoints:    envGet("PROMETHEUS_TELEGRAF_QUALITY_POINTS", 20).(int),
		QualityQuery:     envFileContentExpand("PROMETHEUS_TELEGRAF_QUALITY_QUERY", ""),
		AvailabilityName: envGet("PROMETHEUS_TELEGRAF_AVAILABILITY_NAME", "availability").(string),
		MetricName:       envGet("PROMETHEUS_TELEGRAF_METRIC_NAME", "metric").(string),
		DefaultTags:      strings.Split(envStringExpand("PROMETHEUS_TELEGRAF_DEFAULT_TAGS", ""), ","),
		VarFormat:        envGet("PROMETHEUS_TELEGRAF_VAR_FORMAT", "$%s").(string),
	},
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

			s := gocron.NewScheduler(time.UTC)
			prometheus := vendors.NewPrometheusDiscovery(prometheusDiscoveryOptions, observability)
			if prometheus != nil {
				if !utils.IsEmpty(prometheusDiscoveryOptions.Schedule) {
					schedule(s, prometheusDiscoveryOptions.Schedule, prometheus.Discover)
					logger.Debug("Prometheus discovery enabled on schedule: %s", prometheusDiscoveryOptions.Schedule)
				} else {
					prometheus.Discover()
				}
			} else {
				logger.Debug("Prometheus discovery disabled")
			}
			s.StartAsync()

			// start wait if there are some jobs
			if s.Len() > 0 {
				mainWG.Wait()
			}
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

	flags.StringVar(&prometheusMetricsOptions.URL, "prometheus-metrics-url", prometheusMetricsOptions.URL, "Prometheus metrics endpoint url")
	flags.StringVar(&prometheusMetricsOptions.Listen, "prometheus-metrics-listen", prometheusMetricsOptions.Listen, "Prometheus metrics listen")
	flags.StringVar(&prometheusMetricsOptions.Prefix, "prometheus-metrics-prefix", prometheusMetricsOptions.Prefix, "Prometheus metrics prefix")

	flags.StringVar(&prometheusDiscoveryOptions.URL, "prometheus-url", prometheusDiscoveryOptions.URL, "Prometheus discovery URL")
	flags.IntVar(&prometheusDiscoveryOptions.Timeout, "prometheus-timeout", prometheusDiscoveryOptions.Timeout, "Prometheus discovery timeout in seconds")
	flags.BoolVar(&prometheusDiscoveryOptions.Insecure, "prometheus-insecure", prometheusDiscoveryOptions.Insecure, "Prometheus discovery insecure")
	flags.StringVar(&prometheusDiscoveryOptions.Query, "prometheus-query", prometheusDiscoveryOptions.Query, "Prometheus discovery query")
	flags.StringVar(&prometheusDiscoveryOptions.QueryPeriod, "prometheus-query-period", prometheusDiscoveryOptions.QueryPeriod, "Prometheus discovery query period")
	flags.StringVar(&prometheusDiscoveryOptions.QueryStep, "prometheus-query-step", prometheusDiscoveryOptions.QueryStep, "Prometheus discovery query step")
	flags.StringVar(&prometheusDiscoveryOptions.Service, "prometheus-service", prometheusDiscoveryOptions.Service, "Prometheus discovery service label")
	flags.StringVar(&prometheusDiscoveryOptions.Metric, "prometheus-metric", prometheusDiscoveryOptions.Metric, "Prometheus discovery metric label")
	flags.StringVar(&prometheusDiscoveryOptions.Schedule, "prometheus-schedule", prometheusDiscoveryOptions.Schedule, "Prometheus discovery schedule")
	flags.StringVar(&prometheusDiscoveryOptions.BaseTemplate, "prometheus-base-template", prometheusDiscoveryOptions.BaseTemplate, "Prometheus discovery base template")
	flags.StringVar(&prometheusDiscoveryOptions.Vars, "prometheus-vars", prometheusDiscoveryOptions.Vars, "Prometheus discovery vars")

	flags.StringVar(&prometheusDiscoveryOptions.TelegrafLabels, "prometheus-telegraf-labels", prometheusDiscoveryOptions.TelegrafLabels, "Prometheus discovery telegraf labels")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafTemplate, "prometheus-telegraf-template", prometheusDiscoveryOptions.TelegrafTemplate, "Prometheus discovery telegraf template")
	flags.BoolVar(&prometheusDiscoveryOptions.TelegrafChecksum, "prometheus-telegraf-checksum", prometheusDiscoveryOptions.TelegrafChecksum, "Prometheus discovery telegraf checksum")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.URL, "prometheus-telegraf-url", prometheusDiscoveryOptions.TelegrafOptions.URL, "Prometheus discovery telegraf URL")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Version, "prometheus-telegraf-version", prometheusDiscoveryOptions.TelegrafOptions.Version, "Prometheus discovery telegraf version")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Params, "prometheus-telegraf-params", prometheusDiscoveryOptions.TelegrafOptions.Params, "Prometheus discovery telegraf params")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Interval, "prometheus-telegraf-interval", prometheusDiscoveryOptions.TelegrafOptions.Interval, "Prometheus discovery telegraf interval")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Timeout, "prometheus-telegraf-timeout", prometheusDiscoveryOptions.TelegrafOptions.Timeout, "Prometheus discovery telegraf timeout")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Duration, "prometheus-telegraf-duration", prometheusDiscoveryOptions.TelegrafOptions.Duration, "Prometheus discovery telegraf duration")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.Prefix, "prometheus-telegraf-prefix", prometheusDiscoveryOptions.TelegrafOptions.Prefix, "Prometheus discovery telegraf prefix")

	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.QualityName, "prometheus-telegraf-quality-name", prometheusDiscoveryOptions.TelegrafOptions.QualityName, "Prometheus discovery telegraf quality name")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.QualityRange, "prometheus-telegraf-quality-range", prometheusDiscoveryOptions.TelegrafOptions.QualityRange, "Prometheus discovery telegraf quality range")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.QualityEvery, "prometheus-telegraf-quality-every", prometheusDiscoveryOptions.TelegrafOptions.QualityEvery, "Prometheus discovery telegraf quality every")
	flags.IntVar(&prometheusDiscoveryOptions.TelegrafOptions.QualityPoints, "prometheus-telegraf-quality-points", prometheusDiscoveryOptions.TelegrafOptions.QualityPoints, "Prometheus discovery telegraf quality points")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.QualityQuery, "prometheus-telegraf-quality-query", prometheusDiscoveryOptions.TelegrafOptions.QualityQuery, "Prometheus discovery telegraf quality query")

	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.AvailabilityName, "prometheus-telegraf-availability-name", prometheusDiscoveryOptions.TelegrafOptions.AvailabilityName, "Prometheus discovery telegraf availability name")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.MetricName, "prometheus-telegraf-metric-name", prometheusDiscoveryOptions.TelegrafOptions.MetricName, "Prometheus discovery telegraf metric name")
	flags.StringSliceVar(&prometheusDiscoveryOptions.TelegrafOptions.DefaultTags, "prometheus-telegraf-default-tags", prometheusDiscoveryOptions.TelegrafOptions.DefaultTags, "Prometheus discovery telegraf default tags")
	flags.StringVar(&prometheusDiscoveryOptions.TelegrafOptions.VarFormat, "prometheus-telegraf-var-format", prometheusDiscoveryOptions.TelegrafOptions.VarFormat, "Prometheus discovery telegraf var format")

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
