package telegraf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInputHTTPResponse_UpdateIncludeTags(t *testing.T) {
	tests := []struct {
		name     string
		initial  []string
		toAdd    []string
		expected []string
	}{
		{
			name:     "Add new tags to empty list",
			initial:  nil,
			toAdd:    []string{"tag1", "tag2"},
			expected: []string{"tag1", "tag2"},
		},
		{
			name:     "Add new tags to existing list",
			initial:  []string{"tag1"},
			toAdd:    []string{"tag2", "tag3"},
			expected: []string{"tag1", "tag2", "tag3"},
		},
		{
			name:     "Duplicate tags not added",
			initial:  []string{"tag1", "tag2"},
			toAdd:    []string{"tag2", "tag3"},
			expected: []string{"tag1", "tag2", "tag3"},
		},
		{
			name:     "Empty tags to add leaves list unchanged",
			initial:  []string{"tag1"},
			toAdd:    nil,
			expected: []string{"tag1"},
		},
		{
			name:     "All duplicates produces no change",
			initial:  []string{"a", "b", "c"},
			toAdd:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hr := &InputHTTPResponse{Include: tt.initial}
			hr.updateIncludeTags(tt.toAdd)
			assert.Equal(t, tt.expected, hr.Include)
		})
	}
}
