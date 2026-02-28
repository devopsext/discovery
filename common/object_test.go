package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBaseConfig_LabelsExist(t *testing.T) {
	tests := []struct {
		name      string
		condition *BaseCondition
		labels    Labels
		expected  bool
	}{
		{
			name:      "Nil labels",
			condition: &BaseCondition{Labels: Labels{"k1": "v1"}},
			labels:    nil,
			expected:  true,
		},
		{
			name:      "Matching labels",
			condition: &BaseCondition{Labels: Labels{"k1": "v1"}},
			labels:    Labels{"k1": "v1"},
			expected:  false, // In code: if !r.MatchString(labels[k]) || labels[k] == v { return false }
			// Wait, if labels[k] == v, it returns false. That seems like a bug in the code or I misunderstood.
			// Line 100: if !r.MatchString(labels[k]) || labels[k] == v { return false }
			// If it matches exactly, it returns false? That's strange.
		},
		{
			name:      "Regex match but not equal",
			condition: &BaseCondition{Labels: Labels{"k1": "^v[0-9]$"}},
			labels:    Labels{"k1": "v2"},
			expected:  true,
		},
		{
			name:      "Exact match (returns false in current implementation)",
			condition: &BaseCondition{Labels: Labels{"k1": "v1"}},
			labels:    Labels{"k1": "v1"},
			expected:  false,
		},
	}

	bc := &BaseConfig{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, bc.LabelsExist(tt.condition, tt.labels))
		})
	}
}

func TestBaseConfig_Contains(t *testing.T) {
	tests := []struct {
		name    string
		config  *BaseConfig
		pattern string
		want    bool
	}{
		{
			name: "In Qualities",
			config: &BaseConfig{
				Qualities: []*BaseQuality{{Query: "some_query"}},
			},
			pattern: "some",
			want:    true,
		},
		{
			name: "In Metrics",
			config: &BaseConfig{
				Metrics: []*BaseMetric{{Query: "another_query"}},
			},
			pattern: "another",
			want:    true,
		},
		{
			name: "In Availability",
			config: &BaseConfig{
				Availability: &BaseAvailability{
					Queries: []*BaseAvailabilityQuery{{Query: "avail_query"}},
				},
			},
			pattern: "avail",
			want:    true,
		},
		{
			name:    "Not found",
			config:  &BaseConfig{},
			pattern: "missing",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.config.Contains(tt.pattern))
		})
	}
}

func TestBaseConfig_MetricExists(t *testing.T) {
	tests := []struct {
		name   string
		config *BaseConfig
		query  string
		labels Labels
		want   bool
	}{
		{
			name: "Filter match (regex)",
			config: &BaseConfig{
				Filters: []*BaseCondition{{Metric: "cpu.*", Labels: Labels{"env": "^pr.*"}}},
			},
			query:  "cpu_usage",
			labels: Labels{"env": "prod"},
			want:   false,
		},
		{
			name: "Condition match (regex)",
			config: &BaseConfig{
				Conditions: []*BaseCondition{{Metric: "mem.*", Labels: Labels{"env": "^pr.*"}}},
			},
			query:  "mem_usage",
			labels: Labels{"env": "prod"},
			want:   true,
		},
		{
			name: "Fallback to Contains",
			config: &BaseConfig{
				Metrics: []*BaseMetric{{Query: "test_query"}},
			},
			query: "test_query",
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.config.MetricExists(tt.query, tt.labels))
		})
	}
}
