package discovery

import (
	"testing"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	logs := sreCommon.NewLogs()
	obs := common.NewObservability(logs, nil)
	sinks := common.NewSinks(obs)
	ps := common.NewProcessors(obs, sinks)

	// Use NewLabels so nameTemplate is properly initialized from the Name option.
	l := NewLabels("test",
		common.PrometheusOptions{URL: "http://localhost"},
		LabelsOptions{Query: "up", Name: `{{index . "instance"}}`},
		obs, ps)
	require.NotNil(t, l)

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
			name: "Vector with too few labels (< 2) — skipped",
			vectors: []*common.PrometheusResponseDataVector{
				{Labels: map[string]string{"instance": "host1"}},
			},
			expected: common.LabelsMap{},
		},
		{
			name: "Valid vector — name rendered from instance label",
			vectors: []*common.PrometheusResponseDataVector{
				{Labels: map[string]string{"instance": "host1", "job": "prometheus"}},
			},
			expected: common.LabelsMap{
				"host1": map[string]string{"instance": "host1", "job": "prometheus"},
			},
		},
		{
			name: "Multiple vectors — all keyed by rendered name",
			vectors: []*common.PrometheusResponseDataVector{
				{Labels: map[string]string{"instance": "host1", "job": "node"}},
				{Labels: map[string]string{"instance": "host2", "job": "node"}},
			},
			expected: common.LabelsMap{
				"host1": map[string]string{"instance": "host1", "job": "node"},
				"host2": map[string]string{"instance": "host2", "job": "node"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := l.findLabels(tt.vectors)
			assert.Equal(t, tt.expected, result)
		})
	}
}
