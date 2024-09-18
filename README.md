# Discovery

```
Usage:
  discovery [flags]
  discovery [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  version     Print the version number

Flags:
      --cert-exclusion string                           Cert discovery exclusion
      --cert-names string                               Cert discovery names
      --cert-pattern string                             Cert discovery pattern
      --cert-query string                               Cert discovery query
      --cert-query-period string                        Cert discovery query period
      --cert-query-step string                          Cert discovery query step
      --cert-schedule string                            Cert discovery schedule
      --cert-telegraf-conf string                       Telegraf sink Cert conf
      --cert-telegraf-exclude-root-certs                Telegraf sink Cert exclude root certs
      --cert-telegraf-interval string                   Telegraf sink Cert interval (default "10s")
      --cert-telegraf-read-proxy-url string             Telegraf sink Cert proxy URL
      --cert-telegraf-read-tls-ca string                Telegraf sink Cert TLS CA
      --cert-telegraf-read-tls-cert string              Telegraf sink Cert TLS cert
      --cert-telegraf-read-tls-server-name string       Telegraf sink Cert TLS server name
      --cert-telegraf-server-name string                Telegraf sink Cert server name
      --cert-telegraf-tags strings                      Telegraf sink Cert tags
      --cert-telegraf-template string                   Telegraf sink Cert template
      --cert-telegraf-timeout string                    Telegraf sink Cert timeout (default "5s")
      --cert-telegraf-use-proxy                         Telegraf sink Cert use proxy
      --dns-exclusion string                            DNS discovery domain exclusion
      --dns-names string                                DNS discovery domain names
      --dns-pattern string                              DNS discovery domain pattern
      --dns-query string                                DNS discovery query
      --dns-query-period string                         DNS discovery query period
      --dns-query-step string                           DNS discovery query step
      --dns-schedule string                             DNS discovery schedule
      --ec2-access-key string                           AWS EC2 discovery access key
      --ec2-schedule string                             AWS EC2 discovery schedule
      --ec2-secret-key string                           AWS EC2 discovery secret key
      --files-coverters string                          Files filters
      --files-folder string                             Files folder
      --files-providers string                          Files providers
  -h, --help                                            help for discovery
      --http-exclusion string                           HTTP discovery exclusion
      --http-files string                               Http files
      --http-names string                               HTTP discovery names
      --http-no-ssl string                              HTTP no SSL pattern
      --http-pattern string                             HTTP discovery pattern
      --http-query string                               HTTP discovery query
      --http-query-period string                        HTTP discovery query period
      --http-query-step string                          HTTP discovery query step
      --http-schedule string                            HTTP discovery schedule
      --k8s-app-label string                            K8s discovery app label (default "application")
      --k8s-cluster string                              K8s discovery cluster name (default "undefined")
      --k8s-common-labels stringToString                K8s discovery common labels (default [])
      --k8s-component-label string                      K8s discovery component label (default "component")
      --k8s-config string                               K8s discovery kube config
      --k8s-env string                                  K8s discovery environment (test/prod/etc…) (default "undefined")
      --k8s-instance-label string                       K8s discovery instance label (default "instance")
      --k8s-ns-exclude strings                          K8s discovery namespaces exclude
      --k8s-ns-include strings                          K8s discovery namespaces include
      --k8s-schedule string                             K8s discovery schedule
      --k8s-skip-unknown                                K8s discovery skip unknown applications (default true)
      --labels-name string                              Labels discovery name
      --labels-query string                             Labels discovery query
      --labels-query-period string                      Labels discovery query period
      --labels-query-step string                        Labels discovery query step
      --labels-schedule string                          Labels discovery schedule
      --ldap-config string                              LDAP discovery config
      --ldap-insecure                                   LDAP discovery insecure
      --ldap-password string                            LDAP discovery password map
      --ldap-schedule string                            LDAP discovery schedule
      --ldap-timeout int                                LDAP discovery timeout (default 30)
      --logs strings                                    Log providers: stdout (default [stdout])
      --metrics strings                                 Metric providers: prometheus (default [prometheus])
      --observium-insecure                              Observium discovery insecure
      --observium-password string                       Observium discovery password
      --observium-schedule string                       Observium discovery schedule
      --observium-timeout int                           Observium discovery timeout (default 5)
      --observium-token string                          Observium discovery token
      --observium-url string                            Observium discovery URL
      --observium-user string                           Observium discovery user
      --processor-template-content string               Processor template content or file
      --processor-template-files string                 Processor template files
      --processor-template-providers strings            Processor template providers
      --prometheus-insecure                             Prometheus discovery insecure
      --prometheus-metrics-listen string                Prometheus metrics listen (default ":8080")
      --prometheus-metrics-prefix string                Prometheus metrics prefix
      --prometheus-metrics-url string                   Prometheus metrics endpoint url (default "/metrics")
      --prometheus-names string                         Prometheus discovery names
      --prometheus-timeout int                          Prometheus discovery timeout in seconds (default 30)
      --prometheus-url string                           Prometheus discovery URL
      --pubsub-ack-deadline int                         PubSub subscription ack deadline duration seconds (default 20)
      --pubsub-credentials string                       Credentials for PubSub
      --pubsub-project string                           PubSub project
      --pubsub-retention int                            PubSub subscription retention duration seconds (default 86400)
      --pubsub-subscription string                      PubSub subscription
      --pubsub-topic string                             PubSub topic
      --run-once                                        Run once
      --scheduler-wait                                  Scheduler wait until first try (default true)
      --signal-base-template string                     Signal discovery base template
      --signal-disabled strings                         Signal discovery disabled services
      --signal-field string                             Signal discovery field label
      --signal-files string                             Signal discovery files
      --signal-metric string                            Signal discovery metric label
      --signal-object string                            Signal discovery ident label
      --signal-query string                             Signal discovery query
      --signal-query-period string                      Signal discovery query period
      --signal-query-step string                        Signal discovery query step
      --signal-schedule string                          Signal discovery schedule
      --signal-vars string                              Signal discovery vars
      --sink-file-checksum                              File sink checksum
      --sink-file-providers strings                     File sink providers through
      --sink-file-replacements string                   File sink replacements
      --sink-json-dir string                            Json sink directory
      --sink-json-providers strings                     Json sink providers through
      --sink-observability-discovery-name string        Observability sink discovery name (default "discovery")
      --sink-observability-labels strings               Observability sink labels through
      --sink-observability-providers strings            Observability sink providers through
      --sink-observability-total-name string            Observability sink total name (default "discovered")
      --sink-telegraf-checksum                          Telegraf sink checksum
      --sink-telegraf-dns-conf string                   Telegraf sink DNS conf
      --sink-telegraf-dns-domains string                Telegraf sink DNS domains
      --sink-telegraf-dns-interval string               Telegraf sink DNS interval (default "10s")
      --sink-telegraf-dns-network string                Telegraf sink DNS network (default "upd")
      --sink-telegraf-dns-port int                      Telegraf sink DNS port (default 53)
      --sink-telegraf-dns-record-type string            Telegraf sink DNS record type (default "A")
      --sink-telegraf-dns-servers string                Telegraf sink DNS servers
      --sink-telegraf-dns-tags strings                  Telegraf sink DNS tags
      --sink-telegraf-dns-template string               Telegraf sink DNS template
      --sink-telegraf-dns-timeout int                   Telegraf sink DNS timeout (default 2)
      --sink-telegraf-http-conf string                  Telegraf sink HTTP conf
      --sink-telegraf-http-follow-redirects             Telegraf sink HTTP follow redirects
      --sink-telegraf-http-interval string              Telegraf sink HTTP interval (default "10s")
      --sink-telegraf-http-method string                Telegraf sink HTTP method (default "GET")
      --sink-telegraf-http-status-code int              Telegraf sink HTTP status code
      --sink-telegraf-http-string-match string          Telegraf sink HTTP string match
      --sink-telegraf-http-tags strings                 Telegraf sink HTTP tags
      --sink-telegraf-http-template string              Telegraf sink HTTP template
      --sink-telegraf-http-timeout string               Telegraf sink HTTP timeout (default "5s")
      --sink-telegraf-http-urls string                  Telegraf sink HTTP URLs
      --sink-telegraf-providers strings                 Telegraf sink providers through
      --sink-telegraf-signal-availability-name string   Telegraf sink Signal availability name (default "availability")
      --sink-telegraf-signal-default-tags strings       Telegraf sink Signal default tags
      --sink-telegraf-signal-dir string                 Telegraf sink Signal dir
      --sink-telegraf-signal-duration string            Telegraf sink Signal duration
      --sink-telegraf-signal-file string                Telegraf sink Signal file
      --sink-telegraf-signal-metric-name string         Telegraf sink Signal metric name (default "metric")
      --sink-telegraf-signal-params string              Telegraf sink Signal params
      --sink-telegraf-signal-persist-metrics            Telegraf sink Signal persist metrics
      --sink-telegraf-signal-prefix string              Telegraf sink Signal prefix
      --sink-telegraf-signal-quality-every string       Telegraf sink Signal quality every (default "15s")
      --sink-telegraf-signal-quality-name string        Telegraf sink Signal quality name (default "quality")
      --sink-telegraf-signal-quality-points int         Telegraf sink Signal quality points (default 20)
      --sink-telegraf-signal-quality-query string       Telegraf sink Signal quality query
      --sink-telegraf-signal-quality-range string       Telegraf sink Signal quality range (default "5m")
      --sink-telegraf-signal-tags string                Telegraf sink Signal tags
      --sink-telegraf-signal-timeout string             Telegraf sink Signal timeout (default "5s")
      --sink-telegraf-signal-var-format string          Telegraf sink Signal var format (default "$%s")
      --sink-telegraf-signal-version string             Telegraf sink Signal version (default "v1")
      --sink-telegraf-tcp-conf string                   Telegraf sink TCP conf
      --sink-telegraf-tcp-expect string                 Telegraf sink TCP expect
      --sink-telegraf-tcp-interval string               TTelegraf sink TCP interval (default "10s")
      --sink-telegraf-tcp-read-timeout string           Telegraf sink TCP read timeout (default "3s")
      --sink-telegraf-tcp-send string                   Telegraf sink TCP send
      --sink-telegraf-tcp-tags strings                  Telegraf sink TCP tags
      --sink-telegraf-tcp-template string               Telegraf sink TCP template
      --sink-telegraf-tcp-timeout string                Telegraf sink TCP timeout (default "5s")
      --sink-webserver-cert string                      WebServer sink cert file or content
      --sink-webserver-chain string                     WebServer sink CA chain file or content
      --sink-webserver-insecure                         WebServer sink insecure skip verify
      --sink-webserver-key string                       WebServer sink key file or content
      --sink-webserver-listen string                    WebServer sink listen
      --sink-webserver-name string                      WebServer sink server name
      --sink-webserver-providers strings                WebServer sink providers through
      --sink-webserver-tls                              WebServer sink TLS
      --sink-yaml-dir string                            Yaml sink directory
      --sink-yaml-providers strings                     Yaml sink providers through
      --ssink-telegraf-signal-interval string           Telegraf sink Signal interval (default "10s")
      --stdout-debug                                    Stdout debug
      --stdout-format string                            Stdout format: json, text, template (default "text")
      --stdout-level string                             Stdout level: info, warn, error, debug, panic (default "info")
      --stdout-template string                          Stdout template (default "{{.file}} {{.msg}}")
      --stdout-text-colors                              Stdout text colors (default true)
      --stdout-timestamp-format string                  Stdout timestamp format (default "2006-01-02T15:04:05.999999999Z07:00")
      --tcp-exclusion string                            TCP discovery exclusion
      --tcp-names string                                TCP discovery names
      --tcp-pattern string                              TCP discovery pattern
      --tcp-query string                                TCP discovery query
      --tcp-query-period string                         TCP discovery query period
      --tcp-query-step string                           TCP discovery query step
      --tcp-schedule string                             TCP discovery schedule
      --vcenter-insecure                                VCenter discovery insecure
      --vcenter-password string                         VCenter discovery password
      --vcenter-schedule string                         VCenter discovery schedule
      --vcenter-session string                          VCenter discovery session
      --vcenter-timeout int                             VCenter discovery timeout (default 5)
      --vcenter-url string                              VCenter discovery URL
      --vcenter-user string                             VCenter discovery user
      --zabbix-insecure                                 Zabbix discovery insecure
      --zabbix-password string                          Zabbix discovery password
      --zabbix-schedule string                          Zabbix discovery schedule
      --zabbix-timeout int                              Zabbix discovery timeout (default 5)
      --zabbix-token string                             Zabbix discovery token
      --zabbix-url string                               Zabbix discovery URL
      --zabbix-user string                              Zabbix discovery user
```

## LDAP

LDAP discovery password map is a json map of passwords for LDAP servers. The key is the domain name.

```json
{
  "example.com": {
    "username": "CN=user1,OU=Service Accounts,DC=example,DC=com",
    "password": "password1"
  },
  "example2.com": {
    "username": "CN=user2,OU=Service Accounts,DC=example2,DC=com",
    "password": "password2"
  }
}
```
