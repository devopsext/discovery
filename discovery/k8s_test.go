package discovery

import (
	"testing"

	"github.com/devopsext/discovery/common"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
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

func makeIngressRule(host string, paths map[string]string) networkingv1.IngressRule {
	httpPaths := make([]networkingv1.HTTPIngressPath, 0, len(paths))
	for path, svcName := range paths {
		httpPaths = append(httpPaths, networkingv1.HTTPIngressPath{
			Path: path,
			Backend: networkingv1.IngressBackend{
				Service: &networkingv1.IngressServiceBackend{
					Name: svcName,
				},
			},
		})
	}
	return networkingv1.IngressRule{
		Host: host,
		IngressRuleValue: networkingv1.IngressRuleValue{
			HTTP: &networkingv1.HTTPIngressRuleValue{
				Paths: httpPaths,
			},
		},
	}
}

func makeIngress(name, namespace string, tlsHosts []string, rules ...networkingv1.IngressRule) networkingv1.Ingress {
	var tls []networkingv1.IngressTLS
	if len(tlsHosts) > 0 {
		tls = []networkingv1.IngressTLS{{Hosts: tlsHosts}}
	}
	return networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: networkingv1.IngressSpec{
			TLS:   tls,
			Rules: rules,
		},
	}
}

func makeHTTPPath(path, svcName string, pathType *networkingv1.PathType) networkingv1.HTTPIngressPath {
	return networkingv1.HTTPIngressPath{
		Path:     path,
		PathType: pathType,
		Backend: networkingv1.IngressBackend{
			Service: &networkingv1.IngressServiceBackend{
				Name: svcName,
			},
		},
	}
}

func TestNormalizePath(t *testing.T) {
	prefix := networkingv1.PathTypePrefix
	exact := networkingv1.PathTypeExact
	impl := networkingv1.PathTypeImplementationSpecific

	tests := []struct {
		name     string
		path     string
		pathType *networkingv1.PathType
		expected string
	}{
		{
			name:     "Prefix pathType -> unchanged",
			path:     "/api/v1",
			pathType: &prefix,
			expected: "/api/v1",
		},
		{
			name:     "Exact pathType -> unchanged",
			path:     "/api/v1",
			pathType: &exact,
			expected: "/api/v1",
		},
		{
			name:     "nil pathType -> unchanged",
			path:     "/api/v1",
			pathType: nil,
			expected: "/api/v1",
		},
		{
			name:     "ImplementationSpecific with (.*) only -> empty string",
			path:     "(.*)",
			pathType: &impl,
			expected: "",
		},
		{
			name:     "ImplementationSpecific with /api/(.*) -> /api/",
			path:     "/api/(.*)",
			pathType: &impl,
			expected: "/api/",
		},
		{
			name:     "ImplementationSpecific without (.*) suffix -> unchanged",
			path:     `/api/v\d+`,
			pathType: &impl,
			expected: `/api/v\d+`,
		},
		{
			name:     "ImplementationSpecific with literal path -> unchanged",
			path:     "/api/v1",
			pathType: &impl,
			expected: "/api/v1",
		},
		{
			name:     "ImplementationSpecific with /(.*) -> / (nginx root catch-all)",
			path:     "/(.*)",
			pathType: &impl,
			expected: "/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizePath(tt.path, tt.pathType)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildServiceAppCache(t *testing.T) {
	tests := []struct {
		name     string
		k8s      *K8s
		services []v1.Service
		pods     []v1.Pod
		expected map[string]appCacheEntry
	}{
		{
			name: "fast path: application in selector",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("my-svc", "ns", map[string]string{"application": "my-app"}, 80),
			},
			pods:     nil,
			expected: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
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
			expected: map[string]appCacheEntry{"ns/my-svc": {application: "pod-app"}},
		},
		{
			name: "empty selector -> not in cache",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("headless", "ns", map[string]string{}, 80),
			},
			pods:     nil,
			expected: map[string]appCacheEntry{},
		},
		{
			name: "SkipUnknown=false, no app found -> unknown in cache",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("orphan", "ns", map[string]string{"app": "x"}, 80),
			},
			pods:     nil,
			expected: map[string]appCacheEntry{"ns/orphan": {application: "unknown"}},
		},
		{
			name: "SkipUnknown=true, no app found -> not in cache",
			k8s:  newTestK8s("application", true, nil, nil),
			services: []v1.Service{
				makeSvc("orphan", "ns", map[string]string{"app": "x"}, 80),
			},
			pods:     nil,
			expected: map[string]appCacheEntry{},
		},
		{
			name: "NsInclude filters out other namespaces",
			k8s:  newTestK8s("application", false, []string{"allowed"}, nil),
			services: []v1.Service{
				makeSvc("svc-a", "allowed", map[string]string{"application": "app-a"}, 80),
				makeSvc("svc-b", "blocked", map[string]string{"application": "app-b"}, 80),
			},
			pods:     nil,
			expected: map[string]appCacheEntry{"allowed/svc-a": {application: "app-a"}},
		},
		{
			name: "NsExclude filters out excluded namespace",
			k8s:  newTestK8s("application", false, nil, []string{"kube-system"}),
			services: []v1.Service{
				makeSvc("svc-a", "default", map[string]string{"application": "app-a"}, 80),
				makeSvc("svc-b", "kube-system", map[string]string{"application": "app-b"}, 80),
			},
			pods:     nil,
			expected: map[string]appCacheEntry{"default/svc-a": {application: "app-a"}},
		},
		{
			name: "multiple services all cached",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("svc-a", "ns", map[string]string{"application": "app-a"}, 80),
				makeSvc("svc-b", "ns", map[string]string{"application": "app-b"}, 8080),
			},
			pods:     nil,
			expected: map[string]appCacheEntry{
				"ns/svc-a": {application: "app-a"},
				"ns/svc-b": {application: "app-b"},
			},
		},
		{
			name: "fast path: selector has both application and component",
			k8s: func() *K8s {
				k := newTestK8s("application", false, nil, nil)
				k.options.ComponentLabel = "component"
				return k
			}(),
			services: []v1.Service{
				makeSvc("my-svc", "ns", map[string]string{
					"application": "my-app",
					"component":   "backend",
				}, 80),
			},
			pods:     nil,
			expected: map[string]appCacheEntry{"ns/my-svc": {application: "my-app", component: "backend"}},
		},
		{
			name: "slow path: pod has component label",
			k8s: func() *K8s {
				k := newTestK8s("application", false, nil, nil)
				k.options.ComponentLabel = "component"
				return k
			}(),
			services: []v1.Service{
				makeSvc("my-svc", "ns", map[string]string{"app": "x"}, 80),
			},
			pods: []v1.Pod{
				makePod("pod-1", "ns", map[string]string{
					"app":         "x",
					"application": "pod-app",
					"component":   "frontend",
				}),
			},
			expected: map[string]appCacheEntry{"ns/my-svc": {application: "pod-app", component: "frontend"}},
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
		cache    map[string]appCacheEntry
		expected common.SinkMap
	}{
		{
			name: "service in cache emits one key per port",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("my-svc", "ns", map[string]string{"application": "my-app"}, 80),
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				"my-svc.ns.svc.cluster.local:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
		{
			name: "multi-port service emits one key per port",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("multi-svc", "ns", map[string]string{"application": "svc-app"}, 80, 8080, 9090),
			},
			cache: map[string]appCacheEntry{"ns/multi-svc": {application: "svc-app"}},
			expected: common.SinkMap{
				"multi-svc.ns.svc.cluster.local:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "svc-app",
				},
				"multi-svc.ns.svc.cluster.local:8080": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "svc-app",
				},
				"multi-svc.ns.svc.cluster.local:9090": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "svc-app",
				},
			},
		},
		{
			name: "service not in cache -> omitted",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("orphan-svc", "ns", map[string]string{"app": "x"}, 80),
			},
			cache:    map[string]appCacheEntry{},
			expected: common.SinkMap{},
		},
		{
			name: "empty selector -> omitted",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("headless-svc", "ns", map[string]string{}, 80),
			},
			cache:    map[string]appCacheEntry{},
			expected: common.SinkMap{},
		},
		{
			name: "NsInclude filters out other namespaces",
			k8s:  newTestK8s("application", false, []string{"allowed-ns"}, nil),
			services: []v1.Service{
				makeSvc("svc-a", "allowed-ns", map[string]string{"application": "app-a"}, 80),
				makeSvc("svc-b", "other-ns", map[string]string{"application": "app-b"}, 80),
			},
			cache: map[string]appCacheEntry{
				"allowed-ns/svc-a": {application: "app-a"},
				"other-ns/svc-b":   {application: "app-b"},
			},
			expected: common.SinkMap{
				"svc-a.allowed-ns.svc.cluster.local:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "allowed-ns", "application": "app-a",
				},
			},
		},
		{
			name: "NsExclude filters out excluded namespace",
			k8s:  newTestK8s("application", false, nil, []string{"kube-system"}),
			services: []v1.Service{
				makeSvc("svc-a", "default", map[string]string{"application": "app-a"}, 80),
				makeSvc("svc-b", "kube-system", map[string]string{"application": "app-b"}, 80),
			},
			cache: map[string]appCacheEntry{
				"default/svc-a":     {application: "app-a"},
				"kube-system/svc-b": {application: "app-b"},
			},
			expected: common.SinkMap{
				"svc-a.default.svc.cluster.local:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "default", "application": "app-a",
				},
			},
		},
		{
			name: "entry with component -> labels include component",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("my-svc", "ns", map[string]string{"application": "my-app"}, 80),
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app", component: "backend"}},
			expected: common.SinkMap{
				"my-svc.ns.svc.cluster.local:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns",
					"application": "my-app", "component": "backend",
				},
			},
		},
		{
			name: "entry without component -> labels omit component key",
			k8s:  newTestK8s("application", false, nil, nil),
			services: []v1.Service{
				makeSvc("my-svc", "ns", map[string]string{"application": "my-app"}, 80),
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				"my-svc.ns.svc.cluster.local:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.k8s.servicesToEndpointMap(tt.services, tt.cache)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFindLabelsFromPods(t *testing.T) {
	k := newTestK8s("application", false, nil, nil)
	k.options.ComponentLabel = "component"

	tests := []struct {
		name                string
		pods                []v1.Pod
		namespace           string
		selector            map[string]string
		expectedApplication string
		expectedComponent   string
	}{
		{
			name: "matching pod returns application and component labels",
			pods: []v1.Pod{
				makePod("pod-1", "ns", map[string]string{
					"app":         "x",
					"application": "found-app",
					"component":   "backend",
				}),
			},
			namespace:           "ns",
			selector:            map[string]string{"app": "x"},
			expectedApplication: "found-app",
			expectedComponent:   "backend",
		},
		{
			name: "matching pod with no component label returns empty component",
			pods: []v1.Pod{
				makePod("pod-1", "ns", map[string]string{
					"app":         "x",
					"application": "found-app",
				}),
			},
			namespace:           "ns",
			selector:            map[string]string{"app": "x"},
			expectedApplication: "found-app",
			expectedComponent:   "",
		},
		{
			name:                "no pods -> empty strings",
			pods:                nil,
			namespace:           "ns",
			selector:            map[string]string{"app": "x"},
			expectedApplication: "",
			expectedComponent:   "",
		},
		{
			name: "pod in different namespace not matched",
			pods: []v1.Pod{
				makePod("pod-1", "other-ns", map[string]string{
					"app":         "x",
					"application": "other-app",
					"component":   "backend",
				}),
			},
			namespace:           "ns",
			selector:            map[string]string{"app": "x"},
			expectedApplication: "",
			expectedComponent:   "",
		},
		{
			name: "partial selector match not matched",
			pods: []v1.Pod{
				makePod("pod-1", "ns", map[string]string{
					"app":         "x",
					"application": "app-1",
					"component":   "backend",
				}),
			},
			namespace:           "ns",
			selector:            map[string]string{"app": "x", "component": "frontend"},
			expectedApplication: "",
			expectedComponent:   "",
		},
		{
			name: "returns first match when multiple pods qualify",
			pods: []v1.Pod{
				makePod("pod-1", "ns", map[string]string{
					"app":         "x",
					"application": "first-app",
					"component":   "first-comp",
				}),
				makePod("pod-2", "ns", map[string]string{
					"app":         "x",
					"application": "second-app",
					"component":   "second-comp",
				}),
			},
			namespace:           "ns",
			selector:            map[string]string{"app": "x"},
			expectedApplication: "first-app",
			expectedComponent:   "first-comp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, comp := k.findLabelsFromPods(tt.pods, tt.namespace, tt.selector)
			assert.Equal(t, tt.expectedApplication, app)
			assert.Equal(t, tt.expectedComponent, comp)
		})
	}
}

func TestIngressesToEndpointMap(t *testing.T) {
	tests := []struct {
		name      string
		k8s       *K8s
		ingresses []networkingv1.Ingress
		cache     map[string]appCacheEntry
		expected  common.SinkMap
	}{
		{
			name: "HTTP rule (no TLS) uses port 80",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing", "ns", nil,
					makeIngressRule("api.example.com", map[string]string{"/": "my-svc"}),
				),
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				"api.example.com:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
		{
			name: "HTTPS rule (host in TLS) uses port 443",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing", "ns", []string{"secure.example.com"},
					makeIngressRule("secure.example.com", map[string]string{"/": "my-svc"}),
				),
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				"secure.example.com:443": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
		{
			name: "non-root path included in key",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing", "ns", []string{"api.example.com"},
					makeIngressRule("api.example.com", map[string]string{"/v1": "svc-v1", "/v2": "svc-v2"}),
				),
			},
			cache: map[string]appCacheEntry{
				"ns/svc-v1": {application: "app-v1"},
				"ns/svc-v2": {application: "app-v2"},
			},
			expected: common.SinkMap{
				"api.example.com:443/v1": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "app-v1",
				},
				"api.example.com:443/v2": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "app-v2",
				},
			},
		},
		{
			name: "empty path produces key without path",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing", "ns", nil,
					makeIngressRule("api.example.com", map[string]string{"": "my-svc"}),
				),
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				"api.example.com:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
		{
			name: "empty host rule skipped",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing", "ns", nil,
					makeIngressRule("", map[string]string{"/": "my-svc"}),
				),
			},
			cache:    map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{},
		},
		{
			name: "backend not in cache, SkipUnknown=false -> unknown",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing", "ns", nil,
					makeIngressRule("api.example.com", map[string]string{"/": "missing-svc"}),
				),
			},
			cache: map[string]appCacheEntry{},
			expected: common.SinkMap{
				"api.example.com:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "unknown",
				},
			},
		},
		{
			name: "backend not in cache, SkipUnknown=true -> omitted",
			k8s:  newTestK8s("application", true, nil, nil),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing", "ns", nil,
					makeIngressRule("api.example.com", map[string]string{"/": "missing-svc"}),
				),
			},
			cache:    map[string]appCacheEntry{},
			expected: common.SinkMap{},
		},
		{
			name: "NsInclude filters out other namespaces",
			k8s:  newTestK8s("application", false, []string{"allowed"}, nil),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing-a", "allowed", nil,
					makeIngressRule("a.example.com", map[string]string{"/": "svc-a"}),
				),
				makeIngress("ing-b", "blocked", nil,
					makeIngressRule("b.example.com", map[string]string{"/": "svc-b"}),
				),
			},
			cache: map[string]appCacheEntry{
				"allowed/svc-a": {application: "app-a"},
				"blocked/svc-b": {application: "app-b"},
			},
			expected: common.SinkMap{
				"a.example.com:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "allowed", "application": "app-a",
				},
			},
		},
		{
			name: "NsExclude filters out excluded namespace",
			k8s:  newTestK8s("application", false, nil, []string{"kube-system"}),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing-a", "default", nil,
					makeIngressRule("a.example.com", map[string]string{"/": "svc-a"}),
				),
				makeIngress("ing-b", "kube-system", nil,
					makeIngressRule("b.example.com", map[string]string{"/": "svc-b"}),
				),
			},
			cache: map[string]appCacheEntry{
				"default/svc-a":     {application: "app-a"},
				"kube-system/svc-b": {application: "app-b"},
			},
			expected: common.SinkMap{
				"a.example.com:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "default", "application": "app-a",
				},
			},
		},
		{
			name: "rule with nil HTTP block skipped",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "ns"},
					Spec: networkingv1.IngressSpec{
						Rules: []networkingv1.IngressRule{
							{Host: "tcp.example.com"},
						},
					},
				},
			},
			cache:    map[string]appCacheEntry{},
			expected: common.SinkMap{},
		},
		{
			name: "resource backend (nil Service) skipped",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "ns"},
					Spec: networkingv1.IngressSpec{
						Rules: []networkingv1.IngressRule{
							{
								Host: "api.example.com",
								IngressRuleValue: networkingv1.IngressRuleValue{
									HTTP: &networkingv1.HTTPIngressRuleValue{
										Paths: []networkingv1.HTTPIngressPath{
											{
												Path:    "/",
												Backend: networkingv1.IngressBackend{},
											},
										},
									},
								},
							},
						},
					},
				},
			},
			cache:    map[string]appCacheEntry{},
			expected: common.SinkMap{},
		},
		{
			name: "ImplementationSpecific (.*) alone -> key without path",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "ns"},
					Spec: networkingv1.IngressSpec{
						Rules: []networkingv1.IngressRule{
							{
								Host: "api.example.com",
								IngressRuleValue: networkingv1.IngressRuleValue{
									HTTP: &networkingv1.HTTPIngressRuleValue{
										Paths: []networkingv1.HTTPIngressPath{
											makeHTTPPath("(.*)", "my-svc", func() *networkingv1.PathType {
												pt := networkingv1.PathTypeImplementationSpecific
												return &pt
											}()),
										},
									},
								},
							},
						},
					},
				},
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				"api.example.com:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
		{
			name: "ImplementationSpecific /api/(.*) -> key with /api/",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "ns"},
					Spec: networkingv1.IngressSpec{
						Rules: []networkingv1.IngressRule{
							{
								Host: "api.example.com",
								IngressRuleValue: networkingv1.IngressRuleValue{
									HTTP: &networkingv1.HTTPIngressRuleValue{
										Paths: []networkingv1.HTTPIngressPath{
											makeHTTPPath("/api/(.*)", "my-svc", func() *networkingv1.PathType {
												pt := networkingv1.PathTypeImplementationSpecific
												return &pt
											}()),
										},
									},
								},
							},
						},
					},
				},
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				"api.example.com:80/api/": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
		{
			name: "ImplementationSpecific without (.*) suffix -> key uses raw path",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "ns"},
					Spec: networkingv1.IngressSpec{
						Rules: []networkingv1.IngressRule{
							{
								Host: "api.example.com",
								IngressRuleValue: networkingv1.IngressRuleValue{
									HTTP: &networkingv1.HTTPIngressRuleValue{
										Paths: []networkingv1.HTTPIngressPath{
											makeHTTPPath(`/api/v\d+`, "my-svc", func() *networkingv1.PathType {
												pt := networkingv1.PathTypeImplementationSpecific
												return &pt
											}()),
										},
									},
								},
							},
						},
					},
				},
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				`api.example.com:80/api/v\d+`: common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
		{
			name: "Prefix pathType with non-root path -> unchanged",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "ns"},
					Spec: networkingv1.IngressSpec{
						Rules: []networkingv1.IngressRule{
							{
								Host: "api.example.com",
								IngressRuleValue: networkingv1.IngressRuleValue{
									HTTP: &networkingv1.HTTPIngressRuleValue{
										Paths: []networkingv1.HTTPIngressPath{
											makeHTTPPath("/api/v1", "my-svc", func() *networkingv1.PathType {
												pt := networkingv1.PathTypePrefix
												return &pt
											}()),
										},
									},
								},
							},
						},
					},
				},
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				"api.example.com:80/api/v1": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
		{
			name: "ImplementationSpecific /(.*) -> key without path (nginx root catch-all)",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ing", Namespace: "ns"},
					Spec: networkingv1.IngressSpec{
						Rules: []networkingv1.IngressRule{
							{
								Host: "api.example.com",
								IngressRuleValue: networkingv1.IngressRuleValue{
									HTTP: &networkingv1.HTTPIngressRuleValue{
										Paths: []networkingv1.HTTPIngressPath{
											makeHTTPPath("/(.*)", "my-svc", func() *networkingv1.PathType {
												pt := networkingv1.PathTypeImplementationSpecific
												return &pt
											}()),
										},
									},
								},
							},
						},
					},
				},
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				"api.example.com:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
		{
			name: "entry with component -> labels include component",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing", "ns", nil,
					makeIngressRule("api.example.com", map[string]string{"/": "my-svc"}),
				),
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app", component: "backend"}},
			expected: common.SinkMap{
				"api.example.com:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns",
					"application": "my-app", "component": "backend",
				},
			},
		},
		{
			name: "entry without component -> labels omit component key",
			k8s:  newTestK8s("application", false, nil, nil),
			ingresses: []networkingv1.Ingress{
				makeIngress("ing", "ns", nil,
					makeIngressRule("api.example.com", map[string]string{"/": "my-svc"}),
				),
			},
			cache: map[string]appCacheEntry{"ns/my-svc": {application: "my-app"}},
			expected: common.SinkMap{
				"api.example.com:80": common.Labels{
					"environment": "", "cluster": "", "namespace": "ns", "application": "my-app",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.k8s.ingressesToEndpointMap(tt.ingresses, tt.cache)
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
