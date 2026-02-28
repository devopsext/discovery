package telegraf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInputDNSQuery_UpdateIncludeTags(t *testing.T) {
	tests := []struct {
		name     string
		initial  []string
		toAdd    []string
		expected []string
	}{
		{
			name:     "Add new tags",
			initial:  []string{"tag1"},
			toAdd:    []string{"tag2", "tag3"},
			expected: []string{"tag1", "tag2", "tag3"},
		},
		{
			name:     "Add existing tags",
			initial:  []string{"tag1", "tag2"},
			toAdd:    []string{"tag2", "tag3"},
			expected: []string{"tag1", "tag2", "tag3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dq := &InputDNSQuery{Include: tt.initial}
			dq.updateIncludeTags(tt.toAdd)
			assert.Equal(t, tt.expected, dq.Include)
		})
	}
}
