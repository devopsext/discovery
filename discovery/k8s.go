package discovery

import (
	"context"
	"fmt"
	"maps"
	"path"
	"regexp"
	"strings"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type K8sOptions struct {
	Schedule       string
	ClusterName    string
	NsInclude      []string
	NsExclude      []string
	AppLabel       string
	ComponentLabel string
	InstanceLabel  string
	CommonLabels   map[string]string
	SkipUnknown    bool
	Environment    string
	Config         string
}

type K8s struct {
	client        *kubernetes.Clientset
	options       K8sOptions
	logger        sreCommon.Logger
	observability *common.Observability
	processors    *common.Processors
}

type K8sSinkObject struct {
	sinkMap common.SinkMap
	k8s     *K8s
}

func (kso *K8sSinkObject) Map() common.SinkMap {
	return kso.sinkMap
}

func (kso *K8sSinkObject) Options() any {
	return kso.k8s.options
}

type appCacheEntry struct {
	application string
	component   string
}

func (k *K8s) Discover() {

	k.logger.Debug("K8s has to discover...")

	pods, err := k.client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		k.logger.Error(err)
		return
	}

	var serviceItems []v1.Service
	services, err := k.client.CoreV1().Services("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		k.logger.Error("K8s services listing failed (endpoint discovery degraded): ", err)
	} else {
		serviceItems = services.Items
	}

	var ingressItems []networkingv1.Ingress
	ingresses, err := k.client.NetworkingV1().Ingresses("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		k.logger.Error("K8s ingresses listing failed (endpoint discovery degraded): ", err)
	} else {
		ingressItems = ingresses.Items
	}

	labeledPods := make([]v1.Pod, 0, len(pods.Items))
	for _, pod := range pods.Items {
		if !utils.IsEmpty(pod.Labels[k.options.AppLabel]) {
			labeledPods = append(labeledPods, pod)
		}
	}

	cache := k.buildServiceAppCache(serviceItems, labeledPods)

	endpoints := k.servicesToEndpointMap(serviceItems, cache)
	// Ingress entries overwrite service entries on key collision (ingresses are authoritative for host-based routing).
	maps.Copy(endpoints, k.ingressesToEndpointMap(ingressItems, cache))

	m := common.SinkMap{}
	//m["workload"] = k.podsToSinkMap(testPods())
	//m["image"] = k.podImagesToSinkMap(testPods())
	m["workload"] = k.podsToSinkMap(pods.Items)
	m["image"] = k.podImagesToSinkMap(pods.Items)
	m["endpoint"] = endpoints

	k.processors.Process(k, &K8sSinkObject{
		sinkMap: m,
		k8s:     k,
	})
}

func (k *K8s) podsToSinkMap(pods []v1.Pod) common.SinkMap {
	r := make(common.SinkMap)

	for _, pod := range pods {

		if !utils.IsEmpty(k.options.NsInclude) && !utils.Contains(k.options.NsInclude, pod.Namespace) {
			continue
		}

		if !utils.IsEmpty(k.options.NsExclude) && utils.Contains(k.options.NsExclude, pod.Namespace) {
			continue
		}

		application := common.IfDef(pod.Labels[k.options.AppLabel], "unknown").(string)
		component := common.IfDef(pod.Labels[k.options.ComponentLabel], "unknown").(string)
		instance := common.IfDef(pod.Labels[k.options.InstanceLabel], "").(string)

		if k.options.SkipUnknown && utils.IsEmpty(pod.Labels[k.options.AppLabel]) {
			continue
		}

		if utils.IsEmpty(instance) {
			instance = application
		}

		if component != "unknown" {
			instance = component + "." + instance
		}

		instance = instance + "." + pod.Namespace + "." + k.options.ClusterName

		r[fmt.Sprintf("%s.%s.%s", pod.Name, pod.Namespace, k.options.ClusterName)] = common.MergeLabels(common.Labels{
			"application": application,
			"component":   component,
			"instance":    instance,
			"namespace":   pod.Namespace,
			"cluster":     k.options.ClusterName,
			"node":        pod.Spec.NodeName,
			"ip":          pod.Status.PodIP,
			"environment": k.options.Environment,
			"type":        "container",
			"pod":         pod.Name,
		}, k.options.CommonLabels)
	}

	return r
}

// extractImageNameAndTag takes a Docker image URL and returns the image name and tag.
func extractImageNameAndTag(url string) (string, string, error) {
	re := regexp.MustCompile(`^(?:([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+)(?::(\d+))?\/)?((?:[a-zA-Z0-9_-]*\/)*?)([a-zA-Z0-9_-]+)(?::([\w.-]+))?$`)

	matches := re.FindStringSubmatch(url)
	if matches == nil {
		return "", "", fmt.Errorf("invalid Docker image URL")
	}

	imageName := path.Join(matches[1], matches[3], matches[4])
	tag := matches[5]
	if tag == "" {
		tag = "latest" // Default tag if none is specified
	}

	return imageName, tag, nil
}

// normalizePath normalizes an ingress path for use as an endpoint key.
// For ImplementationSpecific paths ending with "(.*)", the suffix is stripped.
// All other paths are returned unchanged.
func normalizePath(p string, pathType *networkingv1.PathType) string {
	if pathType != nil && *pathType == networkingv1.PathTypeImplementationSpecific {
		p = strings.TrimSuffix(p, "(.*)")
	}
	return p
}

func (k *K8s) podImagesToSinkMap(pods []v1.Pod) common.SinkMap {
	r := make(common.SinkMap)

	for _, pod := range pods {

		if !utils.IsEmpty(k.options.NsInclude) && !utils.Contains(k.options.NsInclude, pod.Namespace) {
			continue
		}

		if !utils.IsEmpty(k.options.NsExclude) && utils.Contains(k.options.NsExclude, pod.Namespace) {
			continue
		}

		application := common.IfDef(pod.Labels[k.options.AppLabel], "unknown").(string)
		component := common.IfDef(pod.Labels[k.options.ComponentLabel], "unknown").(string)

		for _, c := range pod.Spec.Containers {

			// resolve repo and tag from image uri "git.example.org:5000/namespace/image:tag" -> "git.example.org/namespace/image", "tag"
			repo, tag, err := extractImageNameAndTag(c.Image)
			if err != nil {
				k.logger.Error(err)
				continue
			}

			r[fmt.Sprintf("%s.%s.%s.%s", c.Name, pod.Name, pod.Namespace, k.options.ClusterName)] = common.MergeLabels(common.Labels{
				"environment": k.options.Environment,
				"cluster":     k.options.ClusterName,
				"namespace":   pod.Namespace,
				"application": application,
				"component":   component,
				"pod":         pod.Name,
				"container":   c.Name,
				"repo":        repo,
				"version":     tag,
				"node":        pod.Spec.NodeName,
				"type":        "container",
			}, k.options.CommonLabels)
		}
	}

	return r
}

func (k *K8s) servicesToEndpointMap(services []v1.Service, cache map[string]appCacheEntry) common.SinkMap {
	r := make(common.SinkMap)

	for _, svc := range services {
		// Namespace guards applied independently of buildServiceAppCache: defensive against
		// callers that pass a more permissive cache than current filter options would produce.
		if !utils.IsEmpty(k.options.NsInclude) && !utils.Contains(k.options.NsInclude, svc.Namespace) {
			continue
		}
		if !utils.IsEmpty(k.options.NsExclude) && utils.Contains(k.options.NsExclude, svc.Namespace) {
			continue
		}
		// Dead code in normal use: buildServiceAppCache already excludes empty-selector services,
		// so they are never in the cache. Kept as a backstop if the cache contract changes.
		if len(svc.Spec.Selector) == 0 {
			continue
		}

		entry, ok := cache[svc.Namespace+"/"+svc.Name]
		if !ok {
			continue
		}

		fqdn := fmt.Sprintf("%s.%s.svc.cluster.local", svc.Name, svc.Namespace)
		for _, port := range svc.Spec.Ports {
			key := fmt.Sprintf("%s:%d", fqdn, port.Port)
			labels := common.Labels{
				"environment": k.options.Environment,
				"cluster":     k.options.ClusterName,
				"namespace":   svc.Namespace,
				"application": entry.application,
			}
			if entry.component != "" {
				labels["component"] = entry.component
			}
			r[key] = common.MergeLabels(labels, k.options.CommonLabels)
		}
	}

	return r
}

// findLabelsFromPods returns the AppLabel and ComponentLabel values from the first
// pod in namespace whose labels contain all selector key/value pairs.
// pods should be pre-filtered to only those with AppLabel set.
func (k *K8s) findLabelsFromPods(pods []v1.Pod, namespace string, selector map[string]string) (application, component string) {
	for _, pod := range pods {
		if pod.Namespace != namespace {
			continue
		}
		match := true
		for sk, sv := range selector {
			if pod.Labels[sk] != sv {
				match = false
				break
			}
		}
		if match {
			return pod.Labels[k.options.AppLabel], pod.Labels[k.options.ComponentLabel]
		}
	}
	return "", ""
}

func (k *K8s) buildServiceAppCache(services []v1.Service, labeledPods []v1.Pod) map[string]appCacheEntry {
	cache := make(map[string]appCacheEntry, len(services))

	for _, svc := range services {
		if !utils.IsEmpty(k.options.NsInclude) && !utils.Contains(k.options.NsInclude, svc.Namespace) {
			continue
		}
		if !utils.IsEmpty(k.options.NsExclude) && utils.Contains(k.options.NsExclude, svc.Namespace) {
			continue
		}
		if len(svc.Spec.Selector) == 0 {
			continue
		}

		application := svc.Spec.Selector[k.options.AppLabel]
		component := svc.Spec.Selector[k.options.ComponentLabel]

		if utils.IsEmpty(application) {
			application, component = k.findLabelsFromPods(labeledPods, svc.Namespace, svc.Spec.Selector)
		}
		if utils.IsEmpty(application) {
			if k.options.SkipUnknown {
				continue
			}
			application = "unknown"
			component = ""
		}

		cache[svc.Namespace+"/"+svc.Name] = appCacheEntry{
			application: application,
			component:   component,
		}
	}

	return cache
}

func (k *K8s) ingressesToEndpointMap(ingresses []networkingv1.Ingress, cache map[string]appCacheEntry) common.SinkMap {
	r := make(common.SinkMap)

	for _, ing := range ingresses {
		if !utils.IsEmpty(k.options.NsInclude) && !utils.Contains(k.options.NsInclude, ing.Namespace) {
			continue
		}
		if !utils.IsEmpty(k.options.NsExclude) && utils.Contains(k.options.NsExclude, ing.Namespace) {
			continue
		}

		tlsHosts := make(map[string]bool)
		for _, tls := range ing.Spec.TLS {
			for _, host := range tls.Hosts {
				tlsHosts[host] = true
			}
		}

		for _, rule := range ing.Spec.Rules {
			if utils.IsEmpty(rule.Host) {
				continue
			}
			if rule.HTTP == nil {
				continue
			}

			port := 80
			if tlsCoversHost(tlsHosts, rule.Host) {
				port = 443
			}

			for _, hp := range rule.HTTP.Paths {
				if hp.Backend.Service == nil {
					continue
				}
				svcName := hp.Backend.Service.Name
				entry, ok := cache[ing.Namespace+"/"+svcName]
				if !ok {
					if k.options.SkipUnknown {
						continue
					}
					entry = appCacheEntry{application: "unknown"}
				}

				p := normalizePath(hp.Path, hp.PathType)
				var key string
				if p == "" || p == "/" {
					key = fmt.Sprintf("%s:%d", rule.Host, port)
				} else {
					key = fmt.Sprintf("%s:%d%s", rule.Host, port, p)
				}
				labels := common.Labels{
					"environment": k.options.Environment,
					"cluster":     k.options.ClusterName,
					"namespace":   ing.Namespace,
					"application": entry.application,
				}
				if entry.component != "" {
					labels["component"] = entry.component
				}
				r[key] = common.MergeLabels(labels, k.options.CommonLabels)
			}
		}
	}

	return r
}

func tlsCoversHost(tlsHosts map[string]bool, host string) bool {
	if tlsHosts[host] {
		return true
	}
	for tlsHost := range tlsHosts {
		if !strings.HasPrefix(tlsHost, "*.") {
			continue
		}
		suffix := tlsHost[1:] // e.g. ".example.com"
		if strings.HasSuffix(host, suffix) {
			label := host[:len(host)-len(suffix)]
			if label != "" && !strings.Contains(label, ".") {
				return true
			}
		}
	}
	return false
}

func (k *K8s) Name() string {
	return "K8s"
}

func (k *K8s) Source() string {
	return k.options.ClusterName
}

func NewK8s(options K8sOptions, obs *common.Observability, processors *common.Processors) *K8s {

	logger := obs.Logs()

	// https://github.com/kubernetes/client-go/blob/master/examples/out-of-cluster-client-configuration/main.go
	config, err := clientcmd.BuildConfigFromFlags("", options.Config)
	if err != nil {
		logger.Debug(err)
		return nil
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		logger.Error(err)
		return nil
	}

	return &K8s{
		client:        client,
		options:       options,
		logger:        logger,
		observability: obs,
		processors:    processors,
	}
}
