package discovery

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	capi "github.com/hashicorp/consul/api"
)

type ConsulOptions struct {
	CommonLabels map[string]string
	BaseUrl      string
	Schedule     string
	Workers      int
	Insecure     bool
}

type Consul struct {
	catalog *capi.Catalog
	options ConsulOptions
	source  string
	logger  sreCommon.Logger
	//observability *common.Observability
	processors *common.Processors
}

type ConsulSinkObject struct {
	sinkMap common.SinkMap
	consul  *Consul
}

func (so ConsulSinkObject) Map() common.SinkMap {
	return so.sinkMap
}

func (so ConsulSinkObject) Options() interface{} {
	return so.consul.options
}

func (c *Consul) Discover() {
	services, _, err := c.catalog.Services(&capi.QueryOptions{})
	if err != nil {
		c.logger.Error(err)
		return
	}

	jobs := make(chan string, len(services))
	results := make(chan common.SinkMap, len(services))
	errCh := make(chan error, len(services))
	defer close(results)

	var wg sync.WaitGroup
	worker := func() {
		defer wg.Done()
		for j := range jobs {
			c.logger.Debug(fmt.Sprintf("consul processing service %s", j))

			nodes, _, err := c.catalog.Service(j, "", &capi.QueryOptions{})
			if err != nil {
				// Do not log every error to avoid flooding; aggregate instead via errCh
				errCh <- err
				results <- make(common.SinkMap)
				continue
			}

			local := make(common.SinkMap, len(nodes))
			for _, node := range nodes {
				labels := make(common.Labels)
				labels["service"] = node.ServiceName
				labels["address"] = node.Address
				labels["port"] = strconv.Itoa(node.ServicePort)
				labels["datacenter"] = node.Datacenter
				labels["dns"] = node.NodeMeta["dns"]
				if version, found := node.ServiceMeta["version"]; found {
					labels["version"] = version
				} else if version, found = node.ServiceMeta["label_version"]; found {
					labels["version"] = version
				}
				if application, found := node.ServiceMeta["label_application"]; found {
					labels["application"] = application
				}
				if component, found := node.ServiceMeta["label_component"]; found {
					labels["component"] = component
				}
				tags := getTags(node.ServiceTags)
				for tag, value := range tags {
					switch tag {
					case "version":
						if _, ok := labels["version"]; !ok {
							labels["version"] = value
						}
					case "application":
						if _, ok := labels["application"]; !ok {
							labels["application"] = value
						}
					case "component":
						if _, ok := labels["component"]; !ok {
							labels["component"] = value
						}
					}
				}
				name := fmt.Sprintf("%s@%s", node.ServiceName, node.Node)
				c.logger.Debug("consul found: %s", name)
				local[name] = common.MergeLabels(c.options.CommonLabels, labels)
			}
			results <- local
		}
	}

	// start fixed number of workers
	for w := 0; w < c.options.Workers; w++ {
		wg.Add(1)
		go worker()
	}

	// enqueue jobs
	nServices := len(services)
	for serviceName := range services {
		jobs <- serviceName
	}
	close(jobs)

	// collect results
	sm := make(common.SinkMap, nServices*2)
	for r := 0; r < nServices; r++ {
		part := <-results
		for k, v := range part {
			sm[k] = v
		}
	}

	// wait workers and close error channel for aggregation
	wg.Wait()
	close(errCh)

	// aggregate errors to avoid log flooding
	failedTotal := 0
	errCounts := make(map[string]int)
	for e := range errCh {
		failedTotal++
		errCounts[e.Error()]++
	}
	if failedTotal > 0 {
		var sb strings.Builder
		shown := 0
		for msg, cnt := range errCounts {
			if shown >= 3 {
				break
			}
			if shown > 0 {
				sb.WriteString("; ")
			}
			sb.WriteString(fmt.Sprintf("%dx '%s'", cnt, msg))
			shown++
		}
		c.logger.Error("consul errors: failed to fetch %d/%d services. Unique errors: %d. Top: %s", failedTotal, nServices, len(errCounts), sb.String())
	}

	c.logger.Info("consul discovered object count: %d", len(sm))
	c.processors.Process(c, &ConsulSinkObject{
		sinkMap: sm,
		consul:  c,
	})
}

func getTags(tags []string) map[string]string {
	res := make(map[string]string)
	for _, tag := range tags {
		if strings.HasPrefix(tag, "label_") {
			parts := strings.SplitN(strings.TrimPrefix(tag, "label_"), "=", 2)
			if len(parts) < 2 {
				// Guard against malformed tags like "label_application" with no '='
				continue
			}
			res[parts[0]] = parts[1]
		}
	}
	return res
}

func (c *Consul) Name() string {
	return "Consul"
}

func (c *Consul) Source() string {
	return c.source
}

func NewConsul(options ConsulOptions, obs *common.Observability, processors *common.Processors) common.Discovery {

	if options.BaseUrl == "" {
		obs.Logs().Error("consul options base url is empty")
		return nil
	}

	u, err := url.Parse(options.BaseUrl)
	if err != nil {
		obs.Logs().Error(err.Error())
		return nil
	}

	source := u.Host
	conf := capi.DefaultConfig()
	conf.Address = source
	conf.Scheme = u.Scheme
	conf.TLSConfig.InsecureSkipVerify = options.Insecure

	client, err := capi.NewClient(conf)
	if err != nil {
		obs.Logs().Error(err.Error())
		return nil
	}

	return &Consul{
		options:    options,
		source:     source,
		processors: processors,
		catalog:    client.Catalog(),
		logger:     obs.Logs(),
	}
}
