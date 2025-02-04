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
	"github.com/devopsext/discovery/discovery"
	"github.com/devopsext/discovery/processor"
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
	Logs          []string
	Metrics       []string
	RunOnce       bool
	SchedulerWait bool
}

var rootOptions = RootOptions{
	Logs:          strings.Split(envGet("LOGS", "stdout").(string), ","),
	Metrics:       strings.Split(envGet("METRICS", "prometheus").(string), ","),
	RunOnce:       envGet("RUN_ONCE", false).(bool),
	SchedulerWait: envGet("SCHEDULER_WAIT", true).(bool),
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
	Prefix: envGet("PROMETHEUS_METRICS_PREFIX", "").(string),
}

var dPrometheusOptions = common.PrometheusOptions{
	Names:    envStringExpand("PROMETHEUS_NAMES", ""),
	URL:      envStringExpand("PROMETHEUS_URL", ""),
	Timeout:  envGet("PROMETHEUS_TIMEOUT", 30).(int),
	Insecure: envGet("PROMETHEUS_INSECURE", false).(bool),
}

var dSignalOptions = discovery.SignalOptions{
	Disabled:     strings.Split(envStringExpand("SIGNAL_DISABLED", ""), ","),
	Schedule:     envGet("SIGNAL_SCHEDULE", "").(string),
	Query:        envFileContentExpand("SIGNAL_QUERY", ""),
	QueryPeriod:  envGet("SIGNAL_QUERY_PERIOD", "").(string),
	QueryStep:    envGet("SIGNAL_QUERY_STEP", "").(string),
	Metric:       envGet("SIGNAL_METRIC", "").(string),
	Ident:        envFileContentExpand("SIGNAL_IDENT", ""),
	Field:        envGet("SIGNAL_FIELD", "").(string),
	Files:        envFileContentExpand("SIGNAL_FILES", ""),
	Vars:         envFileContentExpand("SIGNAL_VARS", ""),
	BaseTemplate: envStringExpand("SIGNAL_BASE_TEMPLATE", ""),
	CacheSize:    envGet("SIGNAL_CACHE_SIZE", 0).(int),
}

var dDNSOptions = discovery.DNSOptions{
	Schedule:    envGet("DNS_SCHEDULE", "").(string),
	Query:       envFileContentExpand("DNS_QUERY", ""),
	QueryPeriod: envGet("DNS_QUERY_PERIOD", "").(string),
	QueryStep:   envGet("DNS_QUERY_STEP", "").(string),
	Pattern:     envGet("DNS_PATTERN", "").(string),
	Names:       envFileContentExpand("DNS_NAMES", ""),
	Exclusion:   envGet("DNS_EXCLUSION", "").(string),
}

var dHTTPOptions = discovery.HTTPOptions{
	Schedule:    envGet("HTTP_SCHEDULE", "").(string),
	Query:       envFileContentExpand("HTTP_QUERY", ""),
	QueryPeriod: envGet("HTTP_QUERY_PERIOD", "").(string),
	QueryStep:   envGet("HTTP_QUERY_STEP", "").(string),
	Pattern:     envGet("HTTP_PATTERN", "").(string),
	Names:       envFileContentExpand("HTTP_NAMES", ""),
	Exclusion:   envGet("HTTP_EXCLUSION", "").(string),
	Files:       envFileContentExpand("HTTP_FILES", ""),
	NoSSL:       envGet("HTTP_NO_SSL", "").(string),
	Path:        envFileContentExpand("HTTP_PATH", ""),
}

var dTCPOptions = discovery.TCPOptions{
	Schedule:    envGet("TCP_SCHEDULE", "").(string),
	Query:       envFileContentExpand("TCP_QUERY", ""),
	QueryPeriod: envGet("TCP_QUERY_PERIOD", "").(string),
	QueryStep:   envGet("TCP_QUERY_STEP", "").(string),
	Pattern:     envGet("TCP_PATTERN", "").(string),
	Names:       envFileContentExpand("TCP_NAMES", ""),
	Exclusion:   envGet("TCP_EXCLUSION", "").(string),
}

var dCertOptions = discovery.CertOptions{
	Schedule:    envGet("CERT_SCHEDULE", "").(string),
	Query:       envFileContentExpand("CERT_QUERY", ""),
	QueryPeriod: envGet("CERT_QUERY_PERIOD", "").(string),
	QueryStep:   envGet("CERT_QUERY_STEP", "").(string),
	Pattern:     envGet("CERT_PATTERN", "").(string),
	Names:       envFileContentExpand("CERT_NAMES", ""),
	Exclusion:   envGet("CERT_EXCLUSION", "").(string),
}

var dObserviumOptions = discovery.ObserviumOptions{
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

var dZabbixOptions = discovery.ZabbixOptions{
	Schedule: envGet("ZABBIX_SCHEDULE", "").(string),
	ZabbixOptions: vendors.ZabbixOptions{
		Timeout:  envGet("ZABBIX_TIMEOUT", 5).(int),
		Insecure: envGet("ZABBIX_INSECURE", false).(bool),
		URL:      envGet("ZABBIX_URL", "").(string),
		User:     envGet("ZABBIX_USER", "").(string),
		Password: envGet("ZABBIX_PASSWORD", "").(string),
		Auth:     envGet("ZABBIX_TOKEN", "").(string),
	},
}

var dVCenterOptions = discovery.VCenterOptions{
	Names:         envStringExpand("VCENTER_NAMES", ""),
	Schedule:      envGet("VCENTER_SCHEDULE", "").(string),
	ClusterFilter: envGet("VCENTER_CLUSTER_FILTER", ".*").(string),
	HostFilter:    envGet("VCENTER_HOST_FILTER", ".*").(string),
	VMFilter:      envGet("VCENTER_VM_FILTER", ".*").(string),
	VCenterOptions: vendors.VCenterOptions{
		Timeout:  envGet("VCENTER_TIMEOUT", 5).(int),
		Insecure: envGet("VCENTER_INSECURE", false).(bool),
		URL:      envGet("VCENTER_URL", "").(string),
		User:     envGet("VCENTER_USER", "").(string),
		Password: envGet("VCENTER_PASSWORD", "").(string),
		Session:  envGet("VCENTER_SESSION", "").(string),
	},
}

var dAWSOptions = discovery.AWSDiscoveryOptions{
	AWSOptions: vendors.AWSOptions{
		Accounts:    envGet("AWS_ACCOUNTS", "").(string),
		Role:        envGet("AWS_ROLE", "").(string),
		RoleTimeout: envGet("AWS_ROLE_TIMEOUT", "300").(string),
		AWSKeys: vendors.AWSKeys{
			AccessKey: envGet("AWS_ACCESS_KEY", "").(string),
			SecretKey: envGet("AWS_SECRET_KEY", "").(string),
		},
	},
}

var dAWSEC2Options = discovery.AWSEC2Options{
	Schedule:            envGet("AWS_EC2_SCHEDULE", "").(string),
	AWSDiscoveryOptions: dAWSOptions,
}

var dK8sOptions = discovery.K8sOptions{
	Schedule:       envGet("K8S_SCHEDULE", "").(string), // K8s discovery disabled if empty
	ClusterName:    envGet("K8S_CLUSTER", "undefined").(string),
	NsInclude:      common.RemoveEmptyStrings(strings.Split(envGet("K8S_NS_INCLUDE", "").(string), ",")),
	NsExclude:      common.RemoveEmptyStrings(strings.Split(envGet("K8S_NS_EXCLUDE", "").(string), ",")),
	AppLabel:       envGet("K8S_APP_LABEL", "application").(string),
	ComponentLabel: envGet("K8S_COMPONENT_LABEL", "component").(string),
	InstanceLabel:  envGet("K8S_INSTANCE_LABEL", "instance").(string),
	CommonLabels:   common.StringSliceToMap(common.RemoveEmptyStrings(strings.Split(envGet("K8S_COMMON_LABELS", "").(string), ","))),
	SkipUnknown:    envGet("K8S_SKIP_UNKNOWN", true).(bool),
	Environment:    envGet("K8S_ENV", "undefined").(string),
	Config:         envStringExpand("K8S_CONFIG", ""),
}

var dLdapOptions = discovery.LdapGlobalOptions{
	ConfigString: envStringExpand("LDAP_CONFIGSTRING", ""),
	Password:     envStringExpand("LDAP_PASSWORD", ""),
	Timeout:      envGet("LDAP_TIMEOUT", 30).(int),
	Insecure:     envGet("LDAP_INSECURE", false).(bool),
	Schedule:     envGet("LDAP_SCHEDULE", "").(string),
}

var dPubSubOptions = discovery.PubSubOptions{
	Credentials:  envGet("PUBSUB_CREDENTIALS", "").(string),
	Topic:        envGet("PUBSUB_TOPIC", "").(string),
	Subscription: envGet("PUBSUB_SUBSCRIPTION", "").(string),
	Project:      envGet("PUBSUB_PROJECT", "").(string),
	AckDeadline:  envGet("PUBSUB_ACK_DEADLINE", 20).(int),
	Retention:    envGet("PUBSUB_RETENTION", 86400).(int),
}

var dFilesOptions = discovery.FilesOptions{
	Folder:     envStringExpand("FILES_FOLDER", ""),
	Providers:  envStringExpand("FILES_PROVIDERS", ""),
	Converters: envStringExpand("FILES_CONVERTERS", ""),
}

var dLabelsOptions = discovery.LabelsOptions{
	Schedule:    envGet("LABELS_SCHEDULE", "").(string),
	Query:       envFileContentExpand("LABELS_QUERY", ""),
	QueryPeriod: envGet("LABELS_QUERY_PERIOD", "").(string),
	QueryStep:   envGet("LABELS_QUERY_STEP", "").(string),
	Name:        envFileContentExpand("LABELS_NAME", ""),
}

var dDumbOptions = discovery.DumbOptions{
	Enabled:  envGet("DUMB_ENABLED", false).(bool),
	Schedule: envGet("DUMB_SCHEDULE", "10s").(string),
}

var pTemplateOptions = processor.TemplateOptions{
	Content:   envFileContentExpand("PROCESSOR_TEMPLATE_CONTENT", ""),
	Files:     envFileContentExpand("PROCESSOR_TEMPLATE_FILES", ""),
	Providers: strings.Split(envStringExpand("PROCESSOR_TEMPLATE_PROVIDERS", ""), ","),
}

var sinkFileOptions = sink.FileOptions{
	Checksum:     envGet("SINK_FILE_CHECKSUM", false).(bool),
	Providers:    strings.Split(envStringExpand("SINK_FILE_PROVIDERS", ""), ","),
	Replacements: envGet("SINK_FILE_REPLACEMENTS", "").(string),
}

var sinkJsonOptions = sink.JsonOptions{
	Dir:       envGet("SINK_JSON_DIR", "").(string),
	Providers: strings.Split(envStringExpand("SINK_JSON_PROVIDERS", ""), ","),
}

var sinkYamlOptions = sink.YamlOptions{
	Dir:       envGet("SINK_YAML_DIR", "").(string),
	Providers: strings.Split(envStringExpand("SINK_YAML_PROVIDERS", ""), ","),
}

var sinkTelegrafOptions = sink.TelegrafOptions{
	Providers: strings.Split(envStringExpand("SINK_TELEGRAF_PROVIDERS", ""), ","),
	Checksum:  envGet("SINK_TELEGRAF_CHECKSUM", false).(bool),
	Signal: sink.TelegrafSignalOptions{
		Dir:            envStringExpand("SINK_TELEGRAF_SIGNAL_DIR", ""),
		File:           envFileContentExpand("SINK_TELEGRAF_SIGNAL_FILE", ""),
		Tags:           envFileContentExpand("SINK_TELEGRAF_SIGNAL_TAGS", ""),
		PersistMetrics: envGet("SINK_TELEGRAF_SIGNAL_PERSIST_METRICS", false).(bool),
		Exclusion:      envStringExpand("SINK_TELEGRAF_SIGNAL_EXCLUSION", ""),
		InputPrometheusHttpOptions: telegraf.InputPrometheusHttpOptions{
			Interval:         envGet("SINK_TELEGRAF_SIGNAL_INTERVAL", "10s").(string),
			Version:          envGet("SINK_TELEGRAF_SIGNAL_VERSION", "v1").(string),
			Params:           envGet("SINK_TELEGRAF_SIGNAL_PARAMS", "").(string),
			Duration:         envGet("SINK_TELEGRAF_SIGNAL_DURATION", "").(string),
			Timeout:          envGet("SINK_TELEGRAF_SIGNAL_TIMEOUT", "5s").(string),
			Prefix:           envGet("SINK_TELEGRAF_SIGNAL_PREFIX", "").(string),
			QualityName:      envGet("SINK_TELEGRAF_SIGNAL_QUALITY_NAME", "quality").(string),
			QualityRange:     envGet("SINK_TELEGRAF_SIGNAL_QUALITY_RANGE", "5m").(string),
			QualityEvery:     envGet("SINK_TELEGRAF_SIGNAL_QUALITY_EVERY", "15s").(string),
			QualityPoints:    envGet("SINK_TELEGRAF_SIGNAL_QUALITY_POINTS", 20).(int),
			QualityQuery:     envFileContentExpand("SINK_TELEGRAF_SIGNAL_QUALITY_QUERY", ""),
			AvailabilityName: envGet("SINK_TELEGRAF_SIGNAL_AVAILABILITY_NAME", "availability").(string),
			MetricName:       envGet("SINK_TELEGRAF_SIGNAL_METRIC_NAME", "metric").(string),
			DefaultTags:      strings.Split(envStringExpand("SINK_TELEGRAF_SIGNAL_DEFAULT_TAGS", ""), ","),
			VarFormat:        envGet("SINK_TELEGRAF_SIGNAL_VAR_FORMAT", "$%s").(string),
		},
	},
	Cert: sink.TelegrafCertOptions{
		Conf:     envStringExpand("SINK_TELEGRAF_CERT_CONF", ""),
		Template: envFileContentExpand("SINK_TELEGRAF_CERT_TEMPLATE", ""),
		InputX509CertOptions: telegraf.InputX509CertOptions{
			Interval:         envGet("SINK_TELEGRAF_CERT_INTERVAL", "10s").(string),
			Timeout:          envGet("SINK_TELEGRAF_CERT_TIMEOUT", "5s").(string),
			ServerName:       envGet("SINK_TELEGRAF_CERT_SERVER_NAME", "").(string),
			ExcludeRootCerts: envGet("SINK_TELEGRAF_CERT_EXCLUDE_ROOT_CERTS", false).(bool),
			TLSCA:            envGet("SINK_TELEGRAF_CERT_TLS_CA", "").(string),
			TLSCert:          envGet("SINK_TELEGRAF_CERT_TLS_CERT", "").(string),
			TLSKey:           envGet("SINK_TELEGRAF_CERT_TLS_KEY", "").(string),
			TLSServerName:    envGet("SINK_TELEGRAF_CERT_TLS_SERVER_NAME", "").(string),
			UseProxy:         envGet("SINK_TELEGRAF_CERT_USE_PROXY", false).(bool),
			ProxyURL:         envGet("SINK_TELEGRAF_CERT_PROXY_URL", "").(string),
			Tags:             strings.Split(envStringExpand("SINK_TELEGRAF_CERT_TAGS", ""), ","),
		},
	},
	DNS: sink.TelegrafDNSOptions{
		Conf:     envStringExpand("SINK_TELEGRAF_DNS_CONF", ""),
		Template: envFileContentExpand("SINK_TELEGRAF_DNS_TEMPLATE", ""),
		InputDNSQueryOptions: telegraf.InputDNSQueryOptions{
			Interval:   envGet("SINK_TELEGRAF_DNS_INTERVAL", "10s").(string),
			Servers:    envGet("SINK_TELEGRAF_DNS_SERVERS", "").(string),
			Network:    envGet("SINK_TELEGRAF_DNS_NETWORK", "upd").(string),
			RecordType: envGet("SINK_TELEGRAF_DNS_RECORD_TYPE", "A").(string),
			Port:       envGet("SINK_TELEGRAF_DNS_PORT", 53).(int),
			Timeout:    envGet("SINK_TELEGRAF_DNS_TIMEOUT", 2).(int),
			Tags:       strings.Split(envStringExpand("SINK_TELEGRAF_DNS_TAGS", ""), ","),
		},
	},
	HTTP: sink.TelegrafHTTPOptions{
		Conf:     envStringExpand("SINK_TELEGRAF_HTTP_CONF", ""),
		Template: envFileContentExpand("SINK_TELEGRAF_HTTP_TEMPLATE", ""),
		InputHTTPResponseOptions: telegraf.InputHTTPResponseOptions{
			Interval:        envGet("SINK_TELEGRAF_HTTP_INTERVAL", "10s").(string),
			URLs:            envGet("SINK_TELEGRAF_HTTP_URLS", "").(string),
			Method:          envGet("SINK_TELEGRAF_HTTP_METHOD", "GET").(string),
			FollowRedirects: envGet("SINK_TELEGRAF_HTTP_FOLLOW_REDIRECTS", false).(bool),
			StringMatch:     envGet("SINK_TELEGRAF_HTTP_STRING_MATCH", "").(string),
			StatusCode:      envGet("SINK_TELEGRAF_HTTP_STATUS_CODE", 0).(int),
			Timeout:         envGet("SINK_TELEGRAF_HTTP_TIMEOUT", "5s").(string),
			Tags:            strings.Split(envStringExpand("SINK_TELEGRAF_HTTP_TAGS", ""), ","),
		},
	},
	TCP: sink.TelegrafTCPOptions{
		Conf:     envStringExpand("SINK_TELEGRAF_TCP_CONF", ""),
		Template: envFileContentExpand("SINK_TELEGRAF_TCP_TEMPLATE", ""),
		InputNetResponseOptions: telegraf.InputNetResponseOptions{
			Interval:    envGet("SINK_TELEGRAF_TCP_INTERVAL", "10s").(string),
			Timeout:     envGet("SINK_TELEGRAF_TCP_TIMEOUT", "5s").(string),
			ReadTimeout: envGet("SINK_TELEGRAF_TCP_READ_TIMEOUT", "3s").(string),
			Send:        envGet("SINK_TELEGRAF_TCP_SEND", "").(string),
			Expect:      envGet("SINK_TELEGRAF_TCP_EXPECT", "").(string),
			Tags:        strings.Split(envStringExpand("SINK_TELEGRAF_TCP_TAGS", ""), ","),
		},
	},
}

var sinkObservabilityOptions = sink.ObservabilityOptions{
	DiscoveryName: envGet("SINK_OBSERVABILITY_DISCOVERY_NAME", "discovery").(string),
	TotalName:     envGet("SINK_OBSERVABILITY_TOTAL_NAME", "discovered").(string),
	Providers:     strings.Split(envStringExpand("SINK_OBSERVABILITY_PROVIDERS", ""), ","),
	Labels:        strings.Split(envStringExpand("SINK_OBSERVABILITY_LABELS", ""), ","),
}

var sinkPubSubOptions = sink.PubSubOptions{
	Enabled:     envGet("SINK_PUBSUB_ENABLED", false).(bool),
	Credentials: envGet("SINK_PUBSUB_CREDENTIALS", "").(string),
	ProjectID:   envGet("SINK_PUBSUB_PROJECT", "").(string),
	TopicID:     envGet("SINK_PUBSUB_TOPIC", "").(string),
	Providers:   strings.Split(envStringExpand("SINK_PUBSUB_PROVIDERS", ""), ","),
}

var sinkWebServerOptions = sink.WebServerOptions{
	ServerName: envGet("SINK_WEBSERVER_SERVER_NAME", "").(string),
	Listen:     envGet("SINK_WEBSERVER_LISTEN", "").(string),
	Tls:        envGet("SINK_WEBSERVER_TLS", false).(bool),
	Insecure:   envGet("SINK_WEBSERVER_INSECURE", false).(bool),
	Cert:       envGet("SINK_WEBSERVER_CERT", "").(string),
	Key:        envGet("SINK_WEBSERVER_KEY", "").(string),
	Chain:      envGet("SINK_WEBSERVER_CHAIN", "").(string),
	Providers:  strings.Split(envStringExpand("SINK_WEBSERVER_PROVIDERS", ""), ","),
	RenderTTL:  time.Second * time.Duration(envGet("SINK_WEBSERVER_RENDER_TTL", 300).(int)),
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

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-c
		logs.Info("Exiting...")
		os.Exit(1)
	}()
}

func runSchedule(s *gocron.Scheduler, schedule string, wait bool, jobFun interface{}) {

	var ss *gocron.Scheduler
	if len(strings.Split(schedule, " ")) == 1 {
		ss = s.Every(schedule)
	} else {
		ss = s.Cron(schedule)
	}
	if wait {
		ss = ss.WaitForSchedule()
	}
	_, err := ss.Do(jobFun)
	if err != nil {
		logs.Error("Schedule error: %s", err)
	}
}

func runStandAloneDiscovery(wg *sync.WaitGroup, discovery common.Discovery, logger *sreCommon.Logs) {

	if utils.IsEmpty(discovery) {
		return
	}
	wg.Add(1)
	go func(d common.Discovery) {
		defer wg.Done()
		d.Discover()
	}(discovery)
	logger.Debug("%s: discovery enabled on event", discovery.Name())
}

func runNamedDiscovery(wg *sync.WaitGroup, scheduler *gocron.Scheduler, schedule string, name, value string, discovery common.Discovery, logger *sreCommon.Logs) {

	if utils.IsEmpty(discovery) {
		return
	}
	// run once and return if there is flag
	if rootOptions.RunOnce {
		wg.Add(1)
		go func(d common.Discovery) {
			defer wg.Done()
			d.Discover()
		}(discovery)
		return
	}
	// run on schedule if there is one defined
	if !utils.IsEmpty(schedule) {
		runSchedule(scheduler, schedule, rootOptions.SchedulerWait, discovery.Discover)
		logger.Debug("%s: %s (%s) discovery enabled on schedule: %s", discovery.Name(), name, value, schedule)
	}
}

func runSimpleDiscovery(wg *sync.WaitGroup, scheduler *gocron.Scheduler, schedule string, discovery common.Discovery, logger *sreCommon.Logs) {

	if utils.IsEmpty(discovery) {
		return
	}
	// run once and return if there is flag
	if rootOptions.RunOnce {
		wg.Add(1)
		go func(d common.Discovery) {
			defer wg.Done()
			d.Discover()
		}(discovery)
		return
	}
	// run on schedule if there is one defined
	if !utils.IsEmpty(schedule) {
		runSchedule(scheduler, schedule, rootOptions.SchedulerWait, discovery.Discover)
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
			sinks.Add(sink.NewFile(sinkFileOptions, obs))
			sinks.Add(sink.NewJson(sinkJsonOptions, obs))
			sinks.Add(sink.NewYaml(sinkYamlOptions, obs))
			sinks.Add(sink.NewTelegraf(sinkTelegrafOptions, obs))
			sinks.Add(sink.NewObservability(sinkObservabilityOptions, obs))
			sinks.Add(sink.NewPubSub(sinkPubSubOptions, obs))
			if ws := sink.NewWebServer(sinkWebServerOptions, obs); ws != nil {
				sinks.Add(ws)
				ws.Start(&mainWG)
			}

			processors := common.NewProcessors(obs, sinks)
			processors.Add(processor.NewTemplate(pTemplateOptions, obs, sinks))

			// define scheduler
			scheduler := gocron.NewScheduler(time.UTC)
			wg := &sync.WaitGroup{}

			// run prometheus discoveries for each prometheus name for URLs and run related discoveries
			proms := common.ParseNames(dPrometheusOptions.Names, obs.Logs())
			for _, prom := range proms {

				// create opts based on global prometheus options
				opts := common.PrometheusOptions{}
				err := copier.CopyWithOption(&opts, &dPrometheusOptions, copier.Option{IgnoreEmpty: true, DeepCopy: true})
				if err != nil {
					logger.Error("Prometheus copy error: %s", err)
					continue
				}

				// render prometheus URL
				m := make(map[string]string)
				m["name"] = prom.Name
				m["url"] = prom.URL
				m["user"] = prom.User
				m["password"] = prom.Password
				opts.URL = common.Render(dPrometheusOptions.URL, m, obs)

				if utils.IsEmpty(opts.URL) || utils.IsEmpty(prom.Name) {
					logger.Debug("Prometheus discovery is not found")
					continue
				}
				// fill additional fields
				opts.Names = prom.Name
				opts.User = prom.User
				opts.Password = prom.Password

				runNamedDiscovery(wg, scheduler, dSignalOptions.Schedule, prom.Name, opts.URL, discovery.NewSignal(prom.Name, opts, dSignalOptions, obs, processors), logger)
				runNamedDiscovery(wg, scheduler, dDNSOptions.Schedule, prom.Name, opts.URL, discovery.NewDNS(prom.Name, opts, dDNSOptions, obs, processors), logger)
				runNamedDiscovery(wg, scheduler, dHTTPOptions.Schedule, prom.Name, opts.URL, discovery.NewHTTP(prom.Name, opts, dHTTPOptions, obs, processors), logger)
				runNamedDiscovery(wg, scheduler, dTCPOptions.Schedule, prom.Name, opts.URL, discovery.NewTCP(prom.Name, opts, dTCPOptions, obs, processors), logger)
				runNamedDiscovery(wg, scheduler, dCertOptions.Schedule, prom.Name, opts.URL, discovery.NewCert(prom.Name, opts, dCertOptions, obs, processors), logger)
				runNamedDiscovery(wg, scheduler, dLabelsOptions.Schedule, prom.Name, opts.URL, discovery.NewLabels(prom.Name, opts, dLabelsOptions, obs, processors), logger)
			}

			runSimpleDiscovery(wg, scheduler, dObserviumOptions.Schedule, discovery.NewObservium(dObserviumOptions, obs, processors), logger)
			runSimpleDiscovery(wg, scheduler, dZabbixOptions.Schedule, discovery.NewZabbix(dZabbixOptions, obs, processors), logger)
			runSimpleDiscovery(wg, scheduler, dK8sOptions.Schedule, discovery.NewK8s(dK8sOptions, obs, processors), logger)

			// run vcenter discoveries for each vcenter name for URLs and run related discoveries
			vcenters := common.ParseNames(dVCenterOptions.Names, obs.Logs())
			for _, vcenter := range vcenters {

				// create opts based on global vcenter options
				opts := discovery.VCenterOptions{}
				err := copier.CopyWithOption(&opts, &dVCenterOptions, copier.Option{IgnoreEmpty: true, DeepCopy: true})
				if err != nil {
					logger.Error("VCenter copy error: %s", err)
					continue
				}

				// render vcenter URL
				m := make(map[string]string)
				m["name"] = vcenter.Name
				m["url"] = vcenter.URL
				m["user"] = vcenter.User
				m["password"] = vcenter.Password
				opts.URL = common.Render(dVCenterOptions.URL, m, obs)

				if utils.IsEmpty(opts.URL) || utils.IsEmpty(vcenter.Name) {
					logger.Debug("VCenter discovery is not found")
					continue
				}
				// fill additional fields
				opts.Names = vcenter.Name
				opts.User = vcenter.User
				opts.Password = vcenter.Password

				runNamedDiscovery(wg, scheduler, dVCenterOptions.Schedule, vcenter.Name, opts.URL, discovery.NewVCenter(vcenter.Name, opts, obs, processors), logger)
			}

			runSimpleDiscovery(wg, scheduler, dAWSEC2Options.Schedule, discovery.NewAWSEC2(dAWSEC2Options, obs, processors), logger)
			runSimpleDiscovery(wg, scheduler, dDumbOptions.Schedule, discovery.NewDumb(dDumbOptions, obs, processors), logger)
			runSimpleDiscovery(wg, scheduler, dLdapOptions.Schedule, discovery.NewLdap(dLdapOptions, obs, processors), logger)

			scheduler.StartAsync()

			// run supportive discoveries without scheduler
			if !rootOptions.RunOnce {
				runStandAloneDiscovery(wg, discovery.NewPubSub(dPubSubOptions, obs, processors), logger)
				runStandAloneDiscovery(wg, discovery.NewFiles(dFilesOptions, obs, processors), logger)
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
	flags.BoolVar(&rootOptions.SchedulerWait, "scheduler-wait", rootOptions.SchedulerWait, "Scheduler wait until first try")

	flags.StringVar(&stdoutOptions.Format, "stdout-format", stdoutOptions.Format, "Stdout format: json, text, template")
	flags.StringVar(&stdoutOptions.Level, "stdout-level", stdoutOptions.Level, "Stdout level: info, warn, error, debug, panic")
	flags.StringVar(&stdoutOptions.Template, "stdout-template", stdoutOptions.Template, "Stdout template")
	flags.StringVar(&stdoutOptions.TimestampFormat, "stdout-timestamp-format", stdoutOptions.TimestampFormat, "Stdout timestamp format")
	flags.BoolVar(&stdoutOptions.TextColors, "stdout-text-colors", stdoutOptions.TextColors, "Stdout text colors")
	flags.BoolVar(&stdoutOptions.Debug, "stdout-debug", stdoutOptions.Debug, "Stdout debug")

	flags.StringVar(&prometheusMetricsOptions.URL, "prometheus-metrics-url", prometheusMetricsOptions.URL, "Prometheus metrics endpoint url")
	flags.StringVar(&prometheusMetricsOptions.Listen, "prometheus-metrics-listen", prometheusMetricsOptions.Listen, "Prometheus metrics listen")
	flags.StringVar(&prometheusMetricsOptions.Prefix, "prometheus-metrics-prefix", prometheusMetricsOptions.Prefix, "Prometheus metrics prefix")

	flags.StringVar(&dPrometheusOptions.Names, "prometheus-names", dPrometheusOptions.Names, "Prometheus discovery names")
	flags.StringVar(&dPrometheusOptions.URL, "prometheus-url", dPrometheusOptions.URL, "Prometheus discovery URL")
	flags.IntVar(&dPrometheusOptions.Timeout, "prometheus-timeout", dPrometheusOptions.Timeout, "Prometheus discovery timeout in seconds")
	flags.BoolVar(&dPrometheusOptions.Insecure, "prometheus-insecure", dPrometheusOptions.Insecure, "Prometheus discovery insecure")

	// Signal
	flags.StringVar(&dSignalOptions.Schedule, "signal-schedule", dSignalOptions.Schedule, "Signal discovery schedule")
	flags.StringVar(&dSignalOptions.Query, "signal-query", dSignalOptions.Query, "Signal discovery query")
	flags.StringVar(&dSignalOptions.QueryPeriod, "signal-query-period", dSignalOptions.QueryPeriod, "Signal discovery query period")
	flags.StringVar(&dSignalOptions.QueryStep, "signal-query-step", dSignalOptions.QueryStep, "Signal discovery query step")
	flags.StringVar(&dSignalOptions.Ident, "signal-object", dSignalOptions.Ident, "Signal discovery ident label")
	flags.StringVar(&dSignalOptions.Field, "signal-field", dSignalOptions.Field, "Signal discovery field label")
	flags.StringVar(&dSignalOptions.Metric, "signal-metric", dSignalOptions.Metric, "Signal discovery metric label")
	flags.StringVar(&dSignalOptions.Files, "signal-files", dSignalOptions.Files, "Signal discovery files")
	flags.StringSliceVar(&dSignalOptions.Disabled, "signal-disabled", dSignalOptions.Disabled, "Signal discovery disabled services")
	flags.StringVar(&dSignalOptions.BaseTemplate, "signal-base-template", dSignalOptions.BaseTemplate, "Signal discovery base template")
	flags.StringVar(&dSignalOptions.Vars, "signal-vars", dSignalOptions.Vars, "Signal discovery vars")

	// DNS
	flags.StringVar(&dDNSOptions.Schedule, "dns-schedule", dDNSOptions.Schedule, "DNS discovery schedule")
	flags.StringVar(&dDNSOptions.Query, "dns-query", dDNSOptions.Query, "DNS discovery query")
	flags.StringVar(&dDNSOptions.QueryPeriod, "dns-query-period", dDNSOptions.QueryPeriod, "DNS discovery query period")
	flags.StringVar(&dDNSOptions.QueryStep, "dns-query-step", dDNSOptions.QueryStep, "DNS discovery query step")
	flags.StringVar(&dDNSOptions.Pattern, "dns-pattern", dDNSOptions.Pattern, "DNS discovery domain pattern")
	flags.StringVar(&dDNSOptions.Names, "dns-names", dDNSOptions.Names, "DNS discovery domain names")
	flags.StringVar(&dDNSOptions.Exclusion, "dns-exclusion", dDNSOptions.Exclusion, "DNS discovery domain exclusion")

	// HTTP
	flags.StringVar(&dHTTPOptions.Schedule, "http-schedule", dHTTPOptions.Schedule, "HTTP discovery schedule")
	flags.StringVar(&dHTTPOptions.Query, "http-query", dHTTPOptions.Query, "HTTP discovery query")
	flags.StringVar(&dHTTPOptions.QueryPeriod, "http-query-period", dHTTPOptions.QueryPeriod, "HTTP discovery query period")
	flags.StringVar(&dHTTPOptions.QueryStep, "http-query-step", dHTTPOptions.QueryStep, "HTTP discovery query step")
	flags.StringVar(&dHTTPOptions.Pattern, "http-pattern", dHTTPOptions.Pattern, "HTTP discovery pattern")
	flags.StringVar(&dHTTPOptions.Names, "http-names", dHTTPOptions.Names, "HTTP discovery names")
	flags.StringVar(&dHTTPOptions.Files, "http-files", dHTTPOptions.Files, "Http files")
	flags.StringVar(&dHTTPOptions.Exclusion, "http-exclusion", dHTTPOptions.Exclusion, "HTTP discovery exclusion")
	flags.StringVar(&dHTTPOptions.NoSSL, "http-no-ssl", dHTTPOptions.NoSSL, "HTTP no SSL pattern")

	// TCP
	flags.StringVar(&dTCPOptions.Schedule, "tcp-schedule", dTCPOptions.Schedule, "TCP discovery schedule")
	flags.StringVar(&dTCPOptions.Query, "tcp-query", dTCPOptions.Query, "TCP discovery query")
	flags.StringVar(&dTCPOptions.QueryPeriod, "tcp-query-period", dTCPOptions.QueryPeriod, "TCP discovery query period")
	flags.StringVar(&dTCPOptions.QueryStep, "tcp-query-step", dTCPOptions.QueryStep, "TCP discovery query step")
	flags.StringVar(&dTCPOptions.Pattern, "tcp-pattern", dTCPOptions.Pattern, "TCP discovery pattern")
	flags.StringVar(&dTCPOptions.Names, "tcp-names", dTCPOptions.Names, "TCP discovery names")
	flags.StringVar(&dTCPOptions.Exclusion, "tcp-exclusion", dTCPOptions.Exclusion, "TCP discovery exclusion")

	// CERT
	flags.StringVar(&dCertOptions.Schedule, "cert-schedule", dCertOptions.Schedule, "Cert discovery schedule")
	flags.StringVar(&dCertOptions.Query, "cert-query", dCertOptions.Query, "Cert discovery query")
	flags.StringVar(&dCertOptions.QueryPeriod, "cert-query-period", dCertOptions.QueryPeriod, "Cert discovery query period")
	flags.StringVar(&dCertOptions.QueryStep, "cert-query-step", dCertOptions.QueryStep, "Cert discovery query step")
	flags.StringVar(&dCertOptions.Pattern, "cert-pattern", dCertOptions.Pattern, "Cert discovery pattern")
	flags.StringVar(&dCertOptions.Names, "cert-names", dCertOptions.Names, "Cert discovery names")
	flags.StringVar(&dCertOptions.Exclusion, "cert-exclusion", dCertOptions.Exclusion, "Cert discovery exclusion")

	// Observium
	flags.StringVar(&dObserviumOptions.Schedule, "observium-schedule", dObserviumOptions.Schedule, "Observium discovery schedule")
	flags.IntVar(&dObserviumOptions.Timeout, "observium-timeout", dObserviumOptions.Timeout, "Observium discovery timeout")
	flags.BoolVar(&dObserviumOptions.Insecure, "observium-insecure", dObserviumOptions.Insecure, "Observium discovery insecure")
	flags.StringVar(&dObserviumOptions.URL, "observium-url", dObserviumOptions.URL, "Observium discovery URL")
	flags.StringVar(&dObserviumOptions.User, "observium-user", dObserviumOptions.User, "Observium discovery user")
	flags.StringVar(&dObserviumOptions.Password, "observium-password", dObserviumOptions.Password, "Observium discovery password")
	flags.StringVar(&dObserviumOptions.Token, "observium-token", dObserviumOptions.Token, "Observium discovery token")

	// Zabbix
	flags.StringVar(&dZabbixOptions.Schedule, "zabbix-schedule", dZabbixOptions.Schedule, "Zabbix discovery schedule")
	flags.IntVar(&dZabbixOptions.Timeout, "zabbix-timeout", dZabbixOptions.Timeout, "Zabbix discovery timeout")
	flags.BoolVar(&dZabbixOptions.Insecure, "zabbix-insecure", dZabbixOptions.Insecure, "Zabbix discovery insecure")
	flags.StringVar(&dZabbixOptions.URL, "zabbix-url", dZabbixOptions.URL, "Zabbix discovery URL")
	flags.StringVar(&dZabbixOptions.User, "zabbix-user", dZabbixOptions.User, "Zabbix discovery user")
	flags.StringVar(&dZabbixOptions.Password, "zabbix-password", dZabbixOptions.Password, "Zabbix discovery password")
	flags.StringVar(&dZabbixOptions.Auth, "zabbix-token", dZabbixOptions.Auth, "Zabbix discovery token")

	// VCenter
	flags.StringVar(&dVCenterOptions.Names, "vcenter-names", dVCenterOptions.Names, "VCenter discovery names")
	flags.StringVar(&dVCenterOptions.Schedule, "vcenter-schedule", dVCenterOptions.Schedule, "VCenter discovery schedule")
	flags.StringVar(&dVCenterOptions.ClusterFilter, "vcenter-cluster-filter", dVCenterOptions.ClusterFilter, "VCenter discovery cluster filter")
	flags.StringVar(&dVCenterOptions.HostFilter, "vcenter-host-filter", dVCenterOptions.HostFilter, "VCenter discovery host filter")
	flags.StringVar(&dVCenterOptions.VMFilter, "vcenter-vm-filter", dVCenterOptions.VMFilter, "VCenter discovery vm filter")
	flags.IntVar(&dVCenterOptions.Timeout, "vcenter-timeout", dVCenterOptions.Timeout, "VCenter discovery timeout")
	flags.BoolVar(&dVCenterOptions.Insecure, "vcenter-insecure", dVCenterOptions.Insecure, "VCenter discovery insecure")
	flags.StringVar(&dVCenterOptions.URL, "vcenter-url", dVCenterOptions.URL, "VCenter discovery URL")
	flags.StringVar(&dVCenterOptions.User, "vcenter-user", dVCenterOptions.User, "VCenter discovery user")
	flags.StringVar(&dVCenterOptions.Password, "vcenter-password", dVCenterOptions.Password, "VCenter discovery password")
	flags.StringVar(&dVCenterOptions.Session, "vcenter-session", dVCenterOptions.Session, "VCenter discovery session")

	// AWS EC2
	flags.StringVar(&dAWSEC2Options.Accounts, "aws-accounts", dAWSEC2Options.Accounts, "AWS discovery accounts")
	flags.StringVar(&dAWSEC2Options.Role, "aws-role", dAWSEC2Options.Role, "AWS discovery role")
	flags.StringVar(&dAWSEC2Options.RoleTimeout, "aws-role-timeout", dAWSEC2Options.RoleTimeout, "AWS discovery role timeout seconds")
	flags.StringVar(&dAWSEC2Options.AccessKey, "aws-access-key", dAWSEC2Options.AccessKey, "AWS discovery access key")
	flags.StringVar(&dAWSEC2Options.SecretKey, "aws-secret-key", dAWSEC2Options.SecretKey, "AWS discovery secret key")
	flags.StringVar(&dAWSEC2Options.Schedule, "aws-ec2-schedule", dAWSEC2Options.Schedule, "AWS discovery schedule")

	// K8s
	flags.StringVar(&dK8sOptions.Schedule, "k8s-schedule", dK8sOptions.Schedule, "K8s discovery schedule")
	flags.StringVar(&dK8sOptions.ClusterName, "k8s-cluster", dK8sOptions.ClusterName, "K8s discovery cluster name")
	flags.StringSliceVar(&dK8sOptions.NsInclude, "k8s-ns-include", dK8sOptions.NsInclude, "K8s discovery namespaces include")
	flags.StringSliceVar(&dK8sOptions.NsExclude, "k8s-ns-exclude", dK8sOptions.NsExclude, "K8s discovery namespaces exclude")
	flags.StringVar(&dK8sOptions.AppLabel, "k8s-app-label", dK8sOptions.AppLabel, "K8s discovery app label")
	flags.StringVar(&dK8sOptions.ComponentLabel, "k8s-component-label", dK8sOptions.ComponentLabel, "K8s discovery component label")
	flags.StringVar(&dK8sOptions.InstanceLabel, "k8s-instance-label", dK8sOptions.InstanceLabel, "K8s discovery instance label")
	flags.StringToStringVarP(&dK8sOptions.CommonLabels, "k8s-common-labels", "", dK8sOptions.CommonLabels, "K8s discovery common labels")
	flags.BoolVar(&dK8sOptions.SkipUnknown, "k8s-skip-unknown", dK8sOptions.SkipUnknown, "K8s discovery skip unknown applications")
	flags.StringVar(&dK8sOptions.Environment, "k8s-env", dK8sOptions.Environment, "K8s discovery environment (test/prod/etc…)")
	flags.StringVar(&dK8sOptions.Config, "k8s-config", dK8sOptions.Config, "K8s discovery kube config")

	// LDAP
	flags.StringVar(&dLdapOptions.ConfigString, "ldap-config", dLdapOptions.ConfigString, "LDAP discovery config")
	flags.StringVar(&dLdapOptions.Password, "ldap-password", dLdapOptions.Password, "LDAP discovery password map")
	flags.IntVar(&dLdapOptions.Timeout, "ldap-timeout", dLdapOptions.Timeout, "LDAP discovery timeout")
	flags.BoolVar(&dLdapOptions.Insecure, "ldap-insecure", dLdapOptions.Insecure, "LDAP discovery insecure")
	flags.StringVar(&dLdapOptions.Schedule, "ldap-schedule", dLdapOptions.Schedule, "LDAP discovery schedule")

	// PubSub
	flags.StringVar(&dPubSubOptions.Credentials, "pubsub-credentials", dPubSubOptions.Credentials, "Credentials for PubSub")
	flags.StringVar(&dPubSubOptions.Topic, "pubsub-topic", dPubSubOptions.Topic, "PubSub topic")
	flags.StringVar(&dPubSubOptions.Subscription, "pubsub-subscription", dPubSubOptions.Subscription, "PubSub subscription")
	flags.StringVar(&dPubSubOptions.Project, "pubsub-project", dPubSubOptions.Project, "PubSub project")
	flags.IntVar(&dPubSubOptions.AckDeadline, "pubsub-ack-deadline", dPubSubOptions.AckDeadline, "PubSub subscription ack deadline duration seconds")
	flags.IntVar(&dPubSubOptions.Retention, "pubsub-retention", dPubSubOptions.Retention, "PubSub subscription retention duration seconds")

	// Files
	flags.StringVar(&dFilesOptions.Folder, "files-folder", dFilesOptions.Folder, "Files folder")
	flags.StringVar(&dFilesOptions.Providers, "files-providers", dFilesOptions.Providers, "Files providers")
	flags.StringVar(&dFilesOptions.Converters, "files-coverters", dFilesOptions.Converters, "Files filters")

	// Labels
	flags.StringVar(&dLabelsOptions.Schedule, "labels-schedule", dLabelsOptions.Schedule, "Labels discovery schedule")
	flags.StringVar(&dLabelsOptions.Query, "labels-query", dLabelsOptions.Query, "Labels discovery query")
	flags.StringVar(&dLabelsOptions.QueryPeriod, "labels-query-period", dLabelsOptions.QueryPeriod, "Labels discovery query period")
	flags.StringVar(&dLabelsOptions.QueryStep, "labels-query-step", dLabelsOptions.QueryStep, "Labels discovery query step")
	flags.StringVar(&dLabelsOptions.Name, "labels-name", dLabelsOptions.Name, "Labels discovery name")

	// Processor Template
	flags.StringVar(&pTemplateOptions.Content, "processor-template-content", pTemplateOptions.Content, "Processor template content or file")
	flags.StringVar(&pTemplateOptions.Files, "processor-template-files", pTemplateOptions.Files, "Processor template files")
	flags.StringSliceVar(&pTemplateOptions.Providers, "processor-template-providers", pTemplateOptions.Providers, "Processor template providers")

	// Sink File
	flags.BoolVar(&sinkFileOptions.Checksum, "sink-file-checksum", sinkFileOptions.Checksum, "File sink checksum")
	flags.StringSliceVar(&sinkFileOptions.Providers, "sink-file-providers", sinkFileOptions.Providers, "File sink providers through")
	flags.StringVar(&sinkFileOptions.Replacements, "sink-file-replacements", sinkFileOptions.Replacements, "File sink replacements")
	// Sink Json
	flags.StringVar(&sinkJsonOptions.Dir, "sink-json-dir", sinkJsonOptions.Dir, "Json sink directory")
	flags.StringSliceVar(&sinkJsonOptions.Providers, "sink-json-providers", sinkJsonOptions.Providers, "Json sink providers through")
	// Sink Yaml
	flags.StringVar(&sinkYamlOptions.Dir, "sink-yaml-dir", sinkYamlOptions.Dir, "Yaml sink directory")
	flags.StringSliceVar(&sinkYamlOptions.Providers, "sink-yaml-providers", sinkYamlOptions.Providers, "Yaml sink providers through")
	// Sink Telegraf general
	flags.StringSliceVar(&sinkTelegrafOptions.Providers, "sink-telegraf-providers", sinkTelegrafOptions.Providers, "Telegraf sink providers through")
	flags.BoolVar(&sinkTelegrafOptions.Checksum, "sink-telegraf-checksum", sinkTelegrafOptions.Checksum, "Telegraf sink checksum")
	// Sink Telegraf Signal
	flags.StringVar(&sinkTelegrafOptions.Signal.Dir, "sink-telegraf-signal-dir", sinkTelegrafOptions.Signal.Dir, "Telegraf sink Signal dir")
	flags.StringVar(&sinkTelegrafOptions.Signal.File, "sink-telegraf-signal-file", sinkTelegrafOptions.Signal.File, "Telegraf sink Signal file")
	flags.StringVar(&sinkTelegrafOptions.Signal.Tags, "sink-telegraf-signal-tags", sinkTelegrafOptions.Signal.Tags, "Telegraf sink Signal tags")
	flags.StringVar(&sinkTelegrafOptions.Signal.Version, "sink-telegraf-signal-version", sinkTelegrafOptions.Signal.Version, "Telegraf sink Signal version")
	flags.StringVar(&sinkTelegrafOptions.Signal.Params, "sink-telegraf-signal-params", sinkTelegrafOptions.Signal.Params, "Telegraf sink Signal params")
	flags.StringVar(&sinkTelegrafOptions.Signal.Interval, "ssink-telegraf-signal-interval", sinkTelegrafOptions.Signal.Interval, "Telegraf sink Signal interval")
	flags.StringVar(&sinkTelegrafOptions.Signal.Timeout, "sink-telegraf-signal-timeout", sinkTelegrafOptions.Signal.Timeout, "Telegraf sink Signal timeout")
	flags.StringVar(&sinkTelegrafOptions.Signal.Duration, "sink-telegraf-signal-duration", sinkTelegrafOptions.Signal.Duration, "Telegraf sink Signal duration")
	flags.StringVar(&sinkTelegrafOptions.Signal.Prefix, "sink-telegraf-signal-prefix", sinkTelegrafOptions.Signal.Prefix, "Telegraf sink Signal prefix")
	flags.StringVar(&sinkTelegrafOptions.Signal.QualityName, "sink-telegraf-signal-quality-name", sinkTelegrafOptions.Signal.QualityName, "Telegraf sink Signal quality name")
	flags.StringVar(&sinkTelegrafOptions.Signal.QualityRange, "sink-telegraf-signal-quality-range", sinkTelegrafOptions.Signal.QualityRange, "Telegraf sink Signal quality range")
	flags.StringVar(&sinkTelegrafOptions.Signal.QualityEvery, "sink-telegraf-signal-quality-every", sinkTelegrafOptions.Signal.QualityEvery, "Telegraf sink Signal quality every")
	flags.IntVar(&sinkTelegrafOptions.Signal.QualityPoints, "sink-telegraf-signal-quality-points", sinkTelegrafOptions.Signal.QualityPoints, "Telegraf sink Signal quality points")
	flags.StringVar(&sinkTelegrafOptions.Signal.QualityQuery, "sink-telegraf-signal-quality-query", sinkTelegrafOptions.Signal.QualityQuery, "Telegraf sink Signal quality query")
	flags.StringVar(&sinkTelegrafOptions.Signal.AvailabilityName, "sink-telegraf-signal-availability-name", sinkTelegrafOptions.Signal.AvailabilityName, "Telegraf sink Signal availability name")
	flags.StringVar(&sinkTelegrafOptions.Signal.MetricName, "sink-telegraf-signal-metric-name", sinkTelegrafOptions.Signal.MetricName, "Telegraf sink Signal metric name")
	flags.StringSliceVar(&sinkTelegrafOptions.Signal.DefaultTags, "sink-telegraf-signal-default-tags", sinkTelegrafOptions.Signal.DefaultTags, "Telegraf sink Signal default tags")
	flags.StringVar(&sinkTelegrafOptions.Signal.VarFormat, "sink-telegraf-signal-var-format", sinkTelegrafOptions.Signal.VarFormat, "Telegraf sink Signal var format")
	flags.BoolVar(&sinkTelegrafOptions.Signal.PersistMetrics, "sink-telegraf-signal-persist-metrics", sinkTelegrafOptions.Signal.PersistMetrics, "Telegraf sink Signal persist metrics")
	// Sink Telegraf Cert
	flags.StringVar(&sinkTelegrafOptions.Cert.Conf, "cert-telegraf-conf", sinkTelegrafOptions.Cert.Conf, "Telegraf sink Cert conf")
	flags.StringVar(&sinkTelegrafOptions.Cert.Template, "cert-telegraf-template", sinkTelegrafOptions.Cert.Template, "Telegraf sink Cert template")
	flags.StringVar(&sinkTelegrafOptions.Cert.Interval, "cert-telegraf-interval", sinkTelegrafOptions.Cert.Interval, "Telegraf sink Cert interval")
	flags.StringVar(&sinkTelegrafOptions.Cert.Timeout, "cert-telegraf-timeout", sinkTelegrafOptions.Cert.Timeout, "Telegraf sink Cert timeout")
	flags.StringVar(&sinkTelegrafOptions.Cert.ServerName, "cert-telegraf-server-name", sinkTelegrafOptions.Cert.ServerName, "Telegraf sink Cert server name")
	flags.BoolVar(&sinkTelegrafOptions.Cert.ExcludeRootCerts, "cert-telegraf-exclude-root-certs", sinkTelegrafOptions.Cert.ExcludeRootCerts, "Telegraf sink Cert exclude root certs")
	flags.StringVar(&sinkTelegrafOptions.Cert.TLSCA, "cert-telegraf-read-tls-ca", sinkTelegrafOptions.Cert.TLSCA, "Telegraf sink Cert TLS CA")
	flags.StringVar(&sinkTelegrafOptions.Cert.TLSCert, "cert-telegraf-read-tls-cert", sinkTelegrafOptions.Cert.TLSCert, "Telegraf sink Cert TLS cert")
	flags.StringVar(&sinkTelegrafOptions.Cert.TLSServerName, "cert-telegraf-read-tls-server-name", sinkTelegrafOptions.Cert.TLSServerName, "Telegraf sink Cert TLS server name")
	flags.BoolVar(&sinkTelegrafOptions.Cert.UseProxy, "cert-telegraf-use-proxy", sinkTelegrafOptions.Cert.UseProxy, "Telegraf sink Cert use proxy")
	flags.StringVar(&sinkTelegrafOptions.Cert.ProxyURL, "cert-telegraf-read-proxy-url", sinkTelegrafOptions.Cert.ProxyURL, "Telegraf sink Cert proxy URL")
	flags.StringSliceVar(&sinkTelegrafOptions.Cert.Tags, "cert-telegraf-tags", sinkTelegrafOptions.Cert.Tags, "Telegraf sink Cert tags")
	// Sink Telegraf DNS
	flags.StringVar(&sinkTelegrafOptions.DNS.Conf, "sink-telegraf-dns-conf", sinkTelegrafOptions.DNS.Conf, "Telegraf sink DNS conf")
	flags.StringVar(&sinkTelegrafOptions.DNS.Template, "sink-telegraf-dns-template", sinkTelegrafOptions.DNS.Template, "Telegraf sink DNS template")
	flags.StringVar(&sinkTelegrafOptions.DNS.Interval, "sink-telegraf-dns-interval", sinkTelegrafOptions.DNS.Interval, "Telegraf sink DNS interval")
	flags.StringVar(&sinkTelegrafOptions.DNS.Servers, "sink-telegraf-dns-servers", sinkTelegrafOptions.DNS.Servers, "Telegraf sink DNS servers")
	flags.StringVar(&sinkTelegrafOptions.DNS.Network, "sink-telegraf-dns-network", sinkTelegrafOptions.DNS.Network, "Telegraf sink DNS network")
	flags.StringVar(&sinkTelegrafOptions.DNS.Domains, "sink-telegraf-dns-domains", sinkTelegrafOptions.DNS.Domains, "Telegraf sink DNS domains")
	flags.StringVar(&sinkTelegrafOptions.DNS.RecordType, "sink-telegraf-dns-record-type", sinkTelegrafOptions.DNS.RecordType, "Telegraf sink DNS record type")
	flags.IntVar(&sinkTelegrafOptions.DNS.Port, "sink-telegraf-dns-port", sinkTelegrafOptions.DNS.Port, "Telegraf sink DNS port")
	flags.IntVar(&sinkTelegrafOptions.DNS.Timeout, "sink-telegraf-dns-timeout", sinkTelegrafOptions.DNS.Timeout, "Telegraf sink DNS timeout")
	flags.StringSliceVar(&sinkTelegrafOptions.DNS.Tags, "sink-telegraf-dns-tags", sinkTelegrafOptions.DNS.Tags, "Telegraf sink DNS tags")
	// Sink Telegraf HTTP
	flags.StringVar(&sinkTelegrafOptions.HTTP.Conf, "sink-telegraf-http-conf", sinkTelegrafOptions.HTTP.Conf, "Telegraf sink HTTP conf")
	flags.StringVar(&sinkTelegrafOptions.HTTP.Template, "sink-telegraf-http-template", sinkTelegrafOptions.HTTP.Template, "Telegraf sink HTTP template")
	flags.StringVar(&sinkTelegrafOptions.HTTP.Interval, "sink-telegraf-http-interval", sinkTelegrafOptions.HTTP.Interval, "Telegraf sink HTTP interval")
	flags.StringVar(&sinkTelegrafOptions.HTTP.URLs, "sink-telegraf-http-urls", sinkTelegrafOptions.HTTP.URLs, "Telegraf sink HTTP URLs")
	flags.StringVar(&sinkTelegrafOptions.HTTP.Method, "sink-telegraf-http-method", sinkTelegrafOptions.HTTP.Method, "Telegraf sink HTTP method")
	flags.BoolVar(&sinkTelegrafOptions.HTTP.FollowRedirects, "sink-telegraf-http-follow-redirects", sinkTelegrafOptions.HTTP.FollowRedirects, "Telegraf sink HTTP follow redirects")
	flags.StringVar(&sinkTelegrafOptions.HTTP.StringMatch, "sink-telegraf-http-string-match", sinkTelegrafOptions.HTTP.StringMatch, "Telegraf sink HTTP string match")
	flags.IntVar(&sinkTelegrafOptions.HTTP.StatusCode, "sink-telegraf-http-status-code", sinkTelegrafOptions.HTTP.StatusCode, "Telegraf sink HTTP status code")
	flags.StringVar(&sinkTelegrafOptions.HTTP.Timeout, "sink-telegraf-http-timeout", sinkTelegrafOptions.HTTP.Timeout, "Telegraf sink HTTP timeout")
	flags.StringSliceVar(&sinkTelegrafOptions.HTTP.Tags, "sink-telegraf-http-tags", sinkTelegrafOptions.HTTP.Tags, "Telegraf sink HTTP tags")
	// Sink Telegraf TCP
	flags.StringVar(&sinkTelegrafOptions.TCP.Conf, "sink-telegraf-tcp-conf", sinkTelegrafOptions.TCP.Conf, "Telegraf sink TCP conf")
	flags.StringVar(&sinkTelegrafOptions.TCP.Template, "sink-telegraf-tcp-template", sinkTelegrafOptions.TCP.Template, "Telegraf sink TCP template")
	flags.StringVar(&sinkTelegrafOptions.TCP.Interval, "sink-telegraf-tcp-interval", sinkTelegrafOptions.TCP.Interval, "TTelegraf sink TCP interval")
	flags.StringVar(&sinkTelegrafOptions.TCP.Send, "sink-telegraf-tcp-send", sinkTelegrafOptions.TCP.Send, "Telegraf sink TCP send")
	flags.StringVar(&sinkTelegrafOptions.TCP.Expect, "sink-telegraf-tcp-expect", sinkTelegrafOptions.TCP.Expect, "Telegraf sink TCP expect")
	flags.StringVar(&sinkTelegrafOptions.TCP.Timeout, "sink-telegraf-tcp-timeout", sinkTelegrafOptions.TCP.Timeout, "Telegraf sink TCP timeout")
	flags.StringVar(&sinkTelegrafOptions.TCP.ReadTimeout, "sink-telegraf-tcp-read-timeout", sinkTelegrafOptions.TCP.ReadTimeout, "Telegraf sink TCP read timeout")
	flags.StringSliceVar(&sinkTelegrafOptions.TCP.Tags, "sink-telegraf-tcp-tags", sinkTelegrafOptions.TCP.Tags, "Telegraf sink TCP tags")
	// Sink Observability
	flags.StringVar(&sinkObservabilityOptions.DiscoveryName, "sink-observability-discovery-name", sinkObservabilityOptions.DiscoveryName, "Observability sink discovery name")
	flags.StringVar(&sinkObservabilityOptions.TotalName, "sink-observability-total-name", sinkObservabilityOptions.TotalName, "Observability sink total name")
	flags.StringSliceVar(&sinkObservabilityOptions.Providers, "sink-observability-providers", sinkObservabilityOptions.Providers, "Observability sink providers through")
	flags.StringSliceVar(&sinkObservabilityOptions.Labels, "sink-observability-labels", sinkObservabilityOptions.Labels, "Observability sink labels through")
	// Sink WebServer
	flags.StringVar(&sinkWebServerOptions.ServerName, "sink-webserver-name", sinkWebServerOptions.ServerName, "WebServer sink server name")
	flags.StringVar(&sinkWebServerOptions.Listen, "sink-webserver-listen", sinkWebServerOptions.Listen, "WebServer sink listen")
	flags.BoolVar(&sinkWebServerOptions.Tls, "sink-webserver-tls", sinkWebServerOptions.Tls, "WebServer sink TLS")
	flags.BoolVar(&sinkWebServerOptions.Insecure, "sink-webserver-insecure", sinkWebServerOptions.Insecure, "WebServer sink insecure skip verify")
	flags.StringVar(&sinkWebServerOptions.Cert, "sink-webserver-cert", sinkWebServerOptions.Cert, "WebServer sink cert file or content")
	flags.StringVar(&sinkWebServerOptions.Key, "sink-webserver-key", sinkWebServerOptions.Key, "WebServer sink key file or content")
	flags.StringVar(&sinkWebServerOptions.Chain, "sink-webserver-chain", sinkWebServerOptions.Chain, "WebServer sink CA chain file or content")
	flags.StringSliceVar(&sinkWebServerOptions.Providers, "sink-webserver-providers", sinkWebServerOptions.Providers, "WebServer sink providers through")

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
