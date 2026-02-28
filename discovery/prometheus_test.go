package discovery

import (
	"testing"

	"github.com/devopsext/discovery/common"
	"github.com/stretchr/testify/assert"
)

func TestPrometheus_Transform(t *testing.T) {
	obs := common.NewObservability(nil, nil)
	p := NewPrometheus("", common.PrometheusOptions{URL: "dumb.example.local"}, PrometheusOptions{Query: "test=count(up) by (name)", QueryKeys: "test={{.name}}"}, obs, nil)
	assert.NotNil(t, p)

	tests := []struct {
		name     string
		vectors  []*common.PrometheusResponseDataVector
		expected common.LabelsMap
	}{
		{
			name: "Single vector",
			vectors: []*common.PrometheusResponseDataVector{
				{
					Labels: map[string]string{
						"__name__": "up",
						"name":     "test_app",
					},
				},
			},
			expected: common.LabelsMap{
				"test_app": common.Labels{
					"__name__": "up",
					"name":     "test_app",
				},
			},
		},
		{
			name: "Multiple vectors",
			vectors: []*common.PrometheusResponseDataVector{
				{
					Labels: map[string]string{"name": "test_app1"},
				},
				{
					Labels: map[string]string{"name": "test_app2"},
				},
			},
			expected: common.LabelsMap{
				"test_app1": common.Labels{"name": "test_app1"},
				"test_app2": common.Labels{"name": "test_app2"},
			},
		},
		{
			name:     "Empty vectors",
			vectors:  []*common.PrometheusResponseDataVector{},
			expected: common.LabelsMap{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := p.transform(0, "test", tt.vectors)
			assert.Equal(t, tt.expected, result)
		})
	}
}
