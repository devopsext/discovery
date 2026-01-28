package discovery

import (
	"context"
	"fmt"
	"path"
	"regexp"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	v1 "k8s.io/api/core/v1"
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

func (kso *K8sSinkObject) Options() interface{} {
	return kso.k8s.options
}

func (k *K8s) Discover() {

	k.logger.Debug("K8s has to discover...")

	pods, err := k.client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		k.logger.Error(err)
		return
	}

	m := common.SinkMap{}
	//m["workload"] = k.podsToSinkMap(testPods())
	//m["image"] = k.podImagesToSinkMap(testPods())
	m["workload"] = k.podsToSinkMap(pods.Items)
	m["image"] = k.podImagesToSinkMap(pods.Items)

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

func (k *K8s) podImagesToSinkMap(pods []v1.Pod) common.SinkMap {
	r := make(common.SinkMap)

	for _, pod := range pods {

		if !utils.IsEmpty(k.options.NsInclude) && !utils.Contains(k.options.NsInclude, pod.Namespace) {
			continue
		}

		if !utils.IsEmpty(k.options.NsExclude) && utils.Contains(k.options.NsExclude, pod.Namespace) {
			continue
		}

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

func testPods() []v1.Pod {
	return []v1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod-1",
				Namespace: "test-ns-1",
				Labels: map[string]string{
					"application": "test-app-1",
					"component":   "test-component-1",
				},
			},
			Spec: v1.PodSpec{
				NodeName: "test-node-1",
				Containers: []v1.Container{
					{
						Name:  "test-container-1",
						Image: "test-image-1",
					},
				},
			},
			Status: v1.PodStatus{
				PodIP: "10.0.0.1",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod-2",
				Namespace: "test-ns-2",
				Labels: map[string]string{
					"application": "test-app-2",
				},
			},
			Spec: v1.PodSpec{
				NodeName: "test-node-2",
				Containers: []v1.Container{
					{
						Name:  "test-container-1",
						Image: "test-image-1:1.1",
					},
					{
						Name:  "test-container-2",
						Image: "test-image-1:notask-21",
					},
				},
			},
			Status: v1.PodStatus{
				PodIP: "10.0.0.2",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod-3",
				Namespace: "test-ns-3",
				Labels: map[string]string{
					"component": "test-component-3",
				},
			},
			Spec: v1.PodSpec{
				NodeName: "test-node-3",
				Containers: []v1.Container{
					{
						Name:  "test-container-1",
						Image: "bla-bla.com/test-image-1:1.1",
					},
					{
						Name:  "test-container-2",
						Image: "bla-bla.com:5000/test-image-1:notask-21",
					},
				},
			},
			Status: v1.PodStatus{
				PodIP: "10.0.0.3",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod-4",
				Namespace: "test-ns-4",
			},
			Spec: v1.PodSpec{
				NodeName: "test-node-4",
			},
			Status: v1.PodStatus{
				PodIP: "10.0.0.4",
			},
		},
	}
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
