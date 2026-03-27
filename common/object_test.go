package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBaseConfig_LabelsExist(t *testing.T) {
	// BaseConfig receiver is unused in the function logic, so an empty struct is fine.
	bc := &BaseConfig{}

	tests := []struct {
		name      string
		condition *BaseCondition
		labels    Labels
		want      bool
	}{
		{
			name:      "Nil labels should return true",
			condition: &BaseCondition{Labels: map[string]string{"app": "backend"}},
			labels:    nil,
			want:      true,
		},
		{
			name:      "Empty condition labels should return true",
			condition: &BaseCondition{Labels: map[string]string{}},
			labels:    Labels{"app": "backend"},
			want:      true,
		},
		{
			name:      "Missing key in provided labels should return false",
			condition: &BaseCondition{Labels: map[string]string{"env": "prod"}},
			labels:    Labels{"app": "backend"}, // "env" key is missing
			want:      false,
		},
		{
			name:      "Exact value match should return true",
			condition: &BaseCondition{Labels: map[string]string{"env": "prod"}},
			labels:    Labels{"env": "prod", "app": "backend"},
			want:      true,
		},
		{
			name:      "Regex value match should return true",
			condition: &BaseCondition{Labels: map[string]string{"env": "^prod-.*"}},
			labels:    Labels{"env": "prod-eu-west"},
			want:      true,
		},
		{
			name:      "Regex value mismatch should return false",
			condition: &BaseCondition{Labels: map[string]string{"env": "^prod-.*"}},
			labels:    Labels{"env": "dev-eu-west"},
			want:      false,
		},
		{
			name: "Invalid regex skips check and continues (evaluates to true if no other constraints fail)",
			// Because your code has `if err != nil { continue }`, it skips the check and proceeds
			condition: &BaseCondition{Labels: map[string]string{"env": "[invalid-regex"}},
			labels:    Labels{"env": "anything"},
			want:      true,
		},
		{
			name:      "Multiple constraints - all matching returns true",
			condition: &BaseCondition{Labels: map[string]string{"env": "prod", "tier": "frontend"}},
			labels:    Labels{"env": "prod", "tier": "frontend", "extra": "data"},
			want:      true,
		},
		{
			name:      "Multiple constraints - one failing returns false",
			condition: &BaseCondition{Labels: map[string]string{"env": "prod", "tier": "frontend"}},
			labels:    Labels{"env": "prod", "tier": "backend"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bc.LabelsExist(tt.condition, tt.labels)
			if got != tt.want {
				t.Errorf("BaseConfig.LabelsExist() = %v, want %v", got, tt.want)
			}
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
