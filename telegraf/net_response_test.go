package telegraf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInputNetResponse_UpdateIncludeTags(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nr := &InputNetResponse{Include: tt.initial}
			nr.updateIncludeTags(tt.toAdd)
			assert.Equal(t, tt.expected, nr.Include)
		})
	}
}
