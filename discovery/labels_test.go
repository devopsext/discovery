package discovery

import (
	"testing"

	"github.com/devopsext/discovery/common"
	"github.com/stretchr/testify/assert"
)

func TestLabels_Basic(t *testing.T) {
	obs := common.NewObservability(nil, nil)
	ps := common.NewProcessors(obs, nil)

	t.Run("Empty URL", func(t *testing.T) {
		l := NewLabels("test", common.PrometheusOptions{}, LabelsOptions{}, obs, ps)
		assert.Nil(t, l)
	})

	t.Run("Empty Query", func(t *testing.T) {
		l := NewLabels("test", common.PrometheusOptions{URL: "http://localhost"}, LabelsOptions{}, obs, ps)
		assert.Nil(t, l)
	})

	t.Run("Empty Name", func(t *testing.T) {
		l := NewLabels("test", common.PrometheusOptions{URL: "http://localhost"}, LabelsOptions{Query: "up"}, obs, ps)
		assert.Nil(t, l)
	})

	t.Run("Valid Name and Source", func(t *testing.T) {
		l := &Labels{source: "src"}
		assert.Equal(t, "Labels", l.Name())
		assert.Equal(t, "src", l.Source())
	})
}

func TestLabels_FindLabels(t *testing.T) {
	obs := common.NewObservability(nil, nil)
	l := &Labels{source: "test", options: LabelsOptions{Name: "{{.instance}}"}, observability: obs}
	// In a real scenario nameTemplate would be initialized

	tests := []struct {
		name     string
		vectors  []*common.PrometheusResponseDataVector
		expected common.LabelsMap
	}{
		{
			name:     "Empty vectors",
			vectors:  []*common.PrometheusResponseDataVector{},
			expected: common.LabelsMap{},
		},
		{
			name: "Vector with too few labels",
			vectors: []*common.PrometheusResponseDataVector{
				{
					Labels: map[string]string{"instance": "host1"},
				},
			},
			expected: common.LabelsMap{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l.findLabels(tt.vectors)
			assert.Equal(t, tt.expected, result)
		})
	}
}
