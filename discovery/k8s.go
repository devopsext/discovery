package discovery

import (
	"context"
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type K8sOptions struct {
	Schedule       string
	ClusterName    string
	NsInclude      []string
	NsExclude      []string
	AppLabel       string
	ComponentLabel string
	InstanceLabel  string
}

type K8s struct {
	client        *kubernetes.Clientset
	options       K8sOptions
	logger        sreCommon.Logger
	observability *common.Observability
	sinks         *common.Sinks
}

type K8sSinkObject struct {
	sinkMap common.SinkMap
	k8s     *K8s
}

func (k *K8sSinkObject) Map() common.SinkMap {
	return k.sinkMap
}

func (k *K8sSinkObject) Options() interface{} {
	return k.k8s.options
}

func (k *K8s) Discover() {

	k.logger.Debug("K8s has to discover...")

	pods, err := k.client.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		k.logger.Error(err)
		return
	}

	k.sinks.Process(k, &K8sSinkObject{
		sinkMap: k.podsToSinkMap(pods.Items),
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

		r[common.IfDef(pod.Labels[k.options.InstanceLabel], pod.Name).(string)] = common.Labels{
			"application": common.IfDef(pod.Labels[k.options.AppLabel], "unknown").(string),
			"component":   common.IfDef(pod.Labels[k.options.ComponentLabel], "unknown").(string),
			"namespace":   pod.Namespace,
			"cluster":     k.options.ClusterName,
			"host":        pod.Spec.NodeName,
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
					"sc/application": "test-app-1",
					"sc/component":   "test-component-1",
				},
			},
			Spec: v1.PodSpec{
				NodeName: "test-node-1",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod-2",
				Namespace: "test-ns-2",
				Labels: map[string]string{
					"sc/application": "test-app-2",
				},
			},
			Spec: v1.PodSpec{
				NodeName: "test-node-2",
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod-3",
				Namespace: "test-ns-3",
				Labels: map[string]string{
					"sc/component": "test-component-3",
				},
			},
			Spec: v1.PodSpec{
				NodeName: "test-node-3",
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
		},
	}
}

func (k *K8s) Name() string {
	return "K8s"
}

func (k *K8s) Source() string {
	return k.options.ClusterName
}

func NewK8s(options K8sOptions, obs *common.Observability, sinks *common.Sinks) *K8s {
	logger := obs.Logs()

	config, err := rest.InClusterConfig()
	if err != nil {
		logger.Error(err)
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
		sinks:         sinks,
	}
}
