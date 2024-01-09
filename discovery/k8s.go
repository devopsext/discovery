package discovery

import (
	"context"
	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/devopsext/utils"
	v1 "k8s.io/api/core/v1"
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
	CommonLabels   map[string]string
	SkipUnknown    bool
	Environment    string
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

func (kso *K8sSinkObject) Map() common.SinkMap {
	return kso.sinkMap
}

func (kso *K8sSinkObject) Options() interface{} {
	return kso.k8s.options
}

func (kso *K8sSinkObject) Slice() []interface{} {
	return common.ConvertLabelMapToSlice(common.ConvertSyncMapToLabelsMap(kso.sinkMap))
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
		//sinkMap: k.podsToSinkMap(testPods()),
		k8s: k,
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

		r[instance] = common.MergeLabels(common.Labels{
			"application": application,
			"component":   component,
			"namespace":   pod.Namespace,
			"cluster":     k.options.ClusterName,
			"node":        pod.Spec.NodeName,
			"ip":          pod.Status.PodIP,
			"environment": k.options.Environment,
			"type":        "container",
			"kind":        "workload",
		}, k.options.CommonLabels)
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
