package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func newTestK8s(appLabel string, skipUnknown bool, nsInclude, nsExclude []string) *K8s {
	return &K8s{
		options: K8sOptions{
			AppLabel:    appLabel,
			SkipUnknown: skipUnknown,
			NsInclude:   nsInclude,
			NsExclude:   nsExclude,
		},
	}
}

func makePod(name, namespace string, labels map[string]string) v1.Pod {
	return v1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
	}
}

func makeSvc(name, namespace string, selector map[string]string, ports ...int32) v1.Service {
	svcPorts := make([]v1.ServicePort, 0, len(ports))
	for _, p := range ports {
		svcPorts = append(svcPorts, v1.ServicePort{Port: p})
	}
	return v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: v1.ServiceSpec{
			Selector: selector,
			Ports:    svcPorts,
		},
	}
}

func TestBuildServiceAppCache(t *testing.T) {
	tests := []struct {
		name     string
		k8s      *K8s
		services []v1.Service
		pods     []v1.Pod
		expected map[string]string
	}{
		{
			name: "fast path: application in selector",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("my-svc", "ns", map[string]string{"application": "my-app"}, 80),
			},
			pods:     nil,
			expected: map[string]string{"ns/my-svc": "my-app"},
		},
		{
			name: "slow path: application from matching pod",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("my-svc", "ns", map[string]string{"app": "x"}, 80),
			},
			pods: []v1.Pod{
				makePod("pod-1", "ns", map[string]string{"app": "x", "application": "pod-app"}),
			},
			expected: map[string]string{"ns/my-svc": "pod-app"},
		},
		{
			name: "empty selector -> not in cache",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("headless", "ns", map[string]string{}, 80),
			},
			pods:     nil,
			expected: map[string]string{},
		},
		{
			name: "SkipUnknown=false, no app found -> unknown in cache",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("orphan", "ns", map[string]string{"app": "x"}, 80),
			},
			pods:     nil,
			expected: map[string]string{"ns/orphan": "unknown"},
		},
		{
			name: "SkipUnknown=true, no app found -> not in cache",
			k8s:  newTestK8s("application", true, nil, nil),
			services: []v1.Service{
				makeSvc("orphan", "ns", map[string]string{"app": "x"}, 80),
			},
			pods:     nil,
			expected: map[string]string{},
		},
		{
			name: "NsInclude filters out other namespaces",
			k8s:  newTestK8s("application", false, []string{"allowed"}, nil),
			services: []v1.Service{
				makeSvc("svc-a", "allowed", map[string]string{"application": "app-a"}, 80),
				makeSvc("svc-b", "blocked", map[string]string{"application": "app-b"}, 80),
			},
			pods:     nil,
			expected: map[string]string{"allowed/svc-a": "app-a"},
		},
		{
			name: "NsExclude filters out excluded namespace",
			k8s:  newTestK8s("application", false, nil, []string{"kube-system"}),
			services: []v1.Service{
				makeSvc("svc-a", "default", map[string]string{"application": "app-a"}, 80),
				makeSvc("svc-b", "kube-system", map[string]string{"application": "app-b"}, 80),
			},
			pods:     nil,
			expected: map[string]string{"default/svc-a": "app-a"},
		},
		{
			name: "multiple services all cached",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("svc-a", "ns", map[string]string{"application": "app-a"}, 80),
				makeSvc("svc-b", "ns", map[string]string{"application": "app-b"}, 8080),
			},
			pods:     nil,
			expected: map[string]string{"ns/svc-a": "app-a", "ns/svc-b": "app-b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.k8s.buildServiceAppCache(tt.services, tt.pods)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestServicesToEndpointMap(t *testing.T) {
	tests := []struct {
		name     string
		k8s      *K8s
		services []v1.Service
		pods     []v1.Pod
		expected map[string]string
	}{
		{
			name: "fast path: application in selector",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("my-svc", "my-ns", map[string]string{"application": "my-app"}, 80),
			},
			pods:     nil,
			expected: map[string]string{"my-svc.my-ns.svc.cluster.local:80": "my-app"},
		},
		{
			name: "slow path: application from matching pod labels",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("my-svc", "my-ns", map[string]string{"app": "my-app"}, 8080),
			},
			pods: []v1.Pod{
				makePod("pod-1", "my-ns", map[string]string{"app": "my-app", "application": "real-app"}),
			},
			expected: map[string]string{"my-svc.my-ns.svc.cluster.local:8080": "real-app"},
		},
		{
			name: "multi-port service emits one key per port",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("multi-svc", "ns", map[string]string{"application": "svc-app"}, 80, 8080, 9090),
			},
			pods: nil,
			expected: map[string]string{
				"multi-svc.ns.svc.cluster.local:80":   "svc-app",
				"multi-svc.ns.svc.cluster.local:8080": "svc-app",
				"multi-svc.ns.svc.cluster.local:9090": "svc-app",
			},
		},
		{
			name: "no matching pods, SkipUnknown=false -> unknown",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("orphan-svc", "ns", map[string]string{"app": "something"}, 80),
			},
			pods:     nil,
			expected: map[string]string{"orphan-svc.ns.svc.cluster.local:80": "unknown"},
		},
		{
			name: "no matching pods, SkipUnknown=true -> omitted",
			k8s:  newTestK8s("application", true, nil, nil),
			services: []v1.Service{
				makeSvc("orphan-svc", "ns", map[string]string{"app": "something"}, 80),
			},
			pods:     nil,
			expected: map[string]string{},
		},
		{
			name: "empty selector -> omitted",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("headless-svc", "ns", map[string]string{}, 80),
			},
			pods:     nil,
			expected: map[string]string{},
		},
		{
			name: "NsInclude filters out other namespaces",
			k8s:  newTestK8s("application", false, []string{"allowed-ns"}, nil),
			services: []v1.Service{
				makeSvc("svc-a", "allowed-ns", map[string]string{"application": "app-a"}, 80),
				makeSvc("svc-b", "other-ns", map[string]string{"application": "app-b"}, 80),
			},
			pods: nil,
			expected: map[string]string{
				"svc-a.allowed-ns.svc.cluster.local:80": "app-a",
			},
		},
		{
			name: "NsExclude filters out excluded namespace",
			k8s:  newTestK8s("application", false, nil, []string{"kube-system"}),
			services: []v1.Service{
				makeSvc("svc-a", "default", map[string]string{"application": "app-a"}, 80),
				makeSvc("svc-b", "kube-system", map[string]string{"application": "app-b"}, 80),
			},
			pods: nil,
			expected: map[string]string{
				"svc-a.default.svc.cluster.local:80": "app-a",
			},
		},
		{
			name: "pod in wrong namespace not matched",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("my-svc", "ns-a", map[string]string{"app": "x"}, 80),
			},
			pods: []v1.Pod{
				makePod("pod-1", "ns-b", map[string]string{"app": "x", "application": "wrong-ns-app"}),
			},
			expected: map[string]string{"my-svc.ns-a.svc.cluster.local:80": "unknown"},
		},
		{
			name: "unlabeled pods excluded from pre-filter",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("my-svc", "ns", map[string]string{"app": "x"}, 80),
			},
			pods: []v1.Pod{
				makePod("unlabeled-pod", "ns", map[string]string{"app": "x"}), // has selector match but no application label
			},
			expected: map[string]string{"my-svc.ns.svc.cluster.local:80": "unknown"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.k8s.servicesToEndpointMap(tt.services, tt.pods)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindApplicationFromPods(t *testing.T) {
	k := newTestK8s("application", false, nil, nil)

	tests := []struct {
		name      string
		pods      []v1.Pod
		namespace string
		selector  map[string]string
		expected  string
	}{
		{
			name: "matching pod returns application label",
			pods: []v1.Pod{
				makePod("pod-1", "ns", map[string]string{"app": "x", "application": "found-app"}),
			},
			namespace: "ns",
			selector:  map[string]string{"app": "x"},
			expected:  "found-app",
		},
		{
			name:      "no pods -> empty string",
			pods:      nil,
			namespace: "ns",
			selector:  map[string]string{"app": "x"},
			expected:  "",
		},
		{
			name: "pod in different namespace not matched",
			pods: []v1.Pod{
				makePod("pod-1", "other-ns", map[string]string{"app": "x", "application": "other-app"}),
			},
			namespace: "ns",
			selector:  map[string]string{"app": "x"},
			expected:  "",
		},
		{
			name: "partial selector match not matched",
			pods: []v1.Pod{
				makePod("pod-1", "ns", map[string]string{"app": "x", "application": "app-1"}),
			},
			namespace: "ns",
			selector:  map[string]string{"app": "x", "component": "backend"},
			expected:  "",
		},
		{
			name: "returns first match when multiple pods qualify",
			pods: []v1.Pod{
				makePod("pod-1", "ns", map[string]string{"app": "x", "application": "first-app"}),
				makePod("pod-2", "ns", map[string]string{"app": "x", "application": "second-app"}),
			},
			namespace: "ns",
			selector:  map[string]string{"app": "x"},
			expected:  "first-app",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := k.findApplicationFromPods(tt.pods, tt.namespace, tt.selector)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractImageNameAndTag(t *testing.T) {
	tests := []struct {
		url          string
		expectedName string
		expectedTag  string
		expectError  bool
	}{
		{
			url:          "nginx:latest",
			expectedName: "nginx",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			url:          "my-registry.io/my-image:v1.2.3",
			expectedName: "my-registry.io/my-image",
			expectedTag:  "v1.2.3",
			expectError:  false,
		},
		{
			url:          "my-registry.io/my-project/my-image:v1.2.3",
			expectedName: "my-registry.io/my-project/my-image",
			expectedTag:  "v1.2.3",
			expectError:  false,
		},
		{
			url:          "my-image",
			expectedName: "my-image",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			url:          "my-registry.io/my-image",
			expectedName: "my-registry.io/my-image",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			url:         "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			name, tag, err := extractImageNameAndTag(tt.url)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedName, name)
				assert.Equal(t, tt.expectedTag, tag)
			}
		})
	}
}
