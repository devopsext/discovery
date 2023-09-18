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
	toolsRender "github.com/devopsext/tools/render"
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

var pubSubOptions = vendors.PubSubOptions{
	Enabled:                 envGet("PUBSUB_ENABLED", false).(bool),
	Credentials:             envGet("PUBSUB_CREDENTIALS", "").(string),
	ProjectID:               envGet("PUBSUB_PROJECT_ID", "").(string),
	TopicID:                 envGet("PUBSUB_TOPIC", "").(string),
	SubscriptionName:        envGet("PUBSUB_SUBSCRIPTION_NAME", "").(string),
	SubscriptionAckDeadline: envGet("PUBSUB_SUBSCRIPTION_ACK_DEADLINE", 20).(int),
	SubscriptionRetention:   envGet("PUBSUB_SUBSCRIPTION_RETENTION", 86400).(int),
	Schedule:                envGet("PUBSUB_SCHEDULE", "").(string),
	CMDBDir:                 envGet("PUBSUB_CMDB_DIR", "").(string),
}

var prometheusDiscoveryOptions = vendors.PrometheusDiscoveryOptions{
	Names:        envStringExpand("PROMETHEUS_NAMES", ""),
	URL:          envStringExpand("PROMETHEUS_URL", ""),
	Timeout:      envGet("PROMETHEUS_TIMEOUT", 30).(int),
	Insecure:     envGet("PROMETHEUS_INSECURE", false).(bool),
	Query:        envFileContentExpand("PROMETHEUS_QUERY", ""),
	QueryPeriod:  envGet("PROMETHEUS_QUERY_PERIOD", "").(string),
	QueryStep:    envGet("PROMETHEUS_QUERY_STEP", "").(string),
	Metric:       envGet("PROMETHEUS_METRIC", "").(string),
	Service:      envGet("PROMETHEUS_SERVICE", "").(string),
	Field:        envGet("PROMETHEUS_FIELD", "").(string),
	Files:        envFileContentExpand("PROMETHEUS_FILES", ""),
	Disabled:     strings.Split(envStringExpand("PROMETHEUS_DISABLED", ""), ","),
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

func render(def string, obj interface{}, observability *common.Observability) string {

	logger := observability.Logs()
	tpl, err := toolsRender.NewTextTemplate(toolsRender.TemplateOptions{Content: def}, observability)
	if err != nil {
		logger.Error(err)
		return def
	}

	s, err := common.RenderTemplate(tpl, def, obj)
	if err != nil {
		logger.Error(err)
		return def
	}
	return s
}

func getPrometheusDiscoveriesByInstances(names string) map[string]string {

	m := make(map[string]string)
	def := "unknown"
	arr := strings.Split(names, ",")
	if len(arr) > 0 {
		index := 0
		for _, v := range arr {

			n := fmt.Sprintf("%s%d", def, index)
			kv := strings.Split(v, "=")
			if len(kv) > 1 {
				name := strings.TrimSpace(kv[0])
				if utils.IsEmpty(name) {
					name = n
				}
				url := strings.TrimSpace(kv[1])
				if !utils.IsEmpty(url) {
					m[name] = url
				}
			} else {
				m[n] = strings.TrimSpace(kv[0])
			}
			index++
		}
	} else {
		m[def] = strings.TrimSpace(names)
	}
	return m
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
			s := gocron.NewScheduler(time.UTC)

			if pubSubOptions.Enabled {
				opts := vendors.PubSubOptions{}
				copier.CopyWithOption(&opts, &pubSubOptions, copier.Option{IgnoreEmpty: true, DeepCopy: true})
				pubsub := vendors.NewPubSubPull(opts, observability)
				if !utils.IsEmpty(pubSubOptions.Schedule) {
					schedule(s, pubSubOptions.Schedule, pubsub.PubSubPull)
					logger.Debug("Pubsub pulling enabled on schedule: %s", pubSubOptions.Schedule)
				} else {
					wg.Add(1)
					go func(p *vendors.PubSub) {
						defer wg.Done()
						p.PubSubPull()
					}(pubsub)
				}
			}

			proms := getPrometheusDiscoveriesByInstances(prometheusDiscoveryOptions.Names)
			for k, v := range proms {

				opts := vendors.PrometheusDiscoveryOptions{}
				copier.CopyWithOption(&opts, &prometheusDiscoveryOptions, copier.Option{IgnoreEmpty: true, DeepCopy: true})

				m := make(map[string]string)
				m["name"] = k
				m["url"] = v
				opts.URL = render(prometheusDiscoveryOptions.URL, m, observability)
				if utils.IsEmpty(opts.TelegrafOptions.URL) {
					opts.TelegrafOptions.URL = opts.URL
				}

				if utils.IsEmpty(opts.URL) || utils.IsEmpty(k) {
					logger.Debug("Prometheus discovery is not found")
					continue
				}

				prometheus := vendors.NewPrometheusDiscovery(k, opts, observability)
				if prometheus != nil {
					if !utils.IsEmpty(prometheusDiscoveryOptions.Schedule) {
						schedule(s, prometheusDiscoveryOptions.Schedule, prometheus.Discover)
						logger.Debug("%s: Prometheus discovery enabled on schedule: %s", v, prometheusDiscoveryOptions.Schedule)
					} else {
						wg.Add(1)
						go func(p *vendors.PrometheusDiscovery) {
							defer wg.Done()
							p.Discover()
						}(prometheus)
					}
				} else {
					logger.Debug("%s: Prometheus discovery disabled", k)
				}
			}
			wg.Wait()
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

	flags.BoolVar(&pubSubOptions.Enabled, "pubsub-enabled", pubSubOptions.Enabled, "Enable pulling from the PubSub topic")
	flags.StringVar(&pubSubOptions.Credentials, "pubsub-credentials", pubSubOptions.Credentials, "Credentials for PubSub")
	flags.StringVar(&pubSubOptions.ProjectID, "pubsub-project-id", pubSubOptions.ProjectID, "PubSub project ID")
	flags.StringVar(&pubSubOptions.TopicID, "pubsub-topic-id", pubSubOptions.TopicID, "PubSub topic ID")
	flags.StringVar(&pubSubOptions.SubscriptionName, "pubsub-subscription-name", pubSubOptions.SubscriptionName, "PubSub subscription name")
	flags.IntVar(&pubSubOptions.SubscriptionAckDeadline, "pubsub-subscription-ack-deadline", pubSubOptions.SubscriptionAckDeadline, "PubSub subscription ack deadline duration seconds")
	flags.IntVar(&pubSubOptions.SubscriptionRetention, "pubsub-subscription-retention", pubSubOptions.SubscriptionRetention, "PubSub subscription retention duration seconds")
	flags.StringVar(&pubSubOptions.Schedule, "pubsub-schedule", pubSubOptions.Schedule, "PubSub pull schedule")
	flags.StringVar(&pubSubOptions.CMDBDir, "pubsub-cmdb-dir", pubSubOptions.CMDBDir, "CMDB directory")

	flags.StringVar(&prometheusDiscoveryOptions.Names, "prometheus-names", prometheusDiscoveryOptions.Names, "Prometheus discovery names")
	flags.StringVar(&prometheusDiscoveryOptions.URL, "prometheus-url", prometheusDiscoveryOptions.URL, "Prometheus discovery URL")
	flags.IntVar(&prometheusDiscoveryOptions.Timeout, "prometheus-timeout", prometheusDiscoveryOptions.Timeout, "Prometheus discovery timeout in seconds")
	flags.BoolVar(&prometheusDiscoveryOptions.Insecure, "prometheus-insecure", prometheusDiscoveryOptions.Insecure, "Prometheus discovery insecure")
	flags.StringVar(&prometheusDiscoveryOptions.Query, "prometheus-query", prometheusDiscoveryOptions.Query, "Prometheus discovery query")
	flags.StringVar(&prometheusDiscoveryOptions.QueryPeriod, "prometheus-query-period", prometheusDiscoveryOptions.QueryPeriod, "Prometheus discovery query period")
	flags.StringVar(&prometheusDiscoveryOptions.QueryStep, "prometheus-query-step", prometheusDiscoveryOptions.QueryStep, "Prometheus discovery query step")
	flags.StringVar(&prometheusDiscoveryOptions.Service, "prometheus-service", prometheusDiscoveryOptions.Service, "Prometheus discovery service label")
	flags.StringVar(&prometheusDiscoveryOptions.Field, "prometheus-field", prometheusDiscoveryOptions.Field, "Prometheus discovery field label")
	flags.StringVar(&prometheusDiscoveryOptions.Metric, "prometheus-metric", prometheusDiscoveryOptions.Metric, "Prometheus discovery metric label")
	flags.StringVar(&prometheusDiscoveryOptions.Files, "prometheus-files", prometheusDiscoveryOptions.Files, "Prometheus discovery files")
	flags.StringSliceVar(&prometheusDiscoveryOptions.Disabled, "prometheus-disabled", prometheusDiscoveryOptions.Disabled, "Prometheus discovery disabled services")
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
