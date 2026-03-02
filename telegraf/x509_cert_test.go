package telegraf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInputX509Cert_UpdateIncludeTags(t *testing.T) {
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
			toAdd:    []string{"tag2"},
			expected: []string{"tag1", "tag2"},
		},
		{
			name:     "Duplicate tags not added",
			initial:  []string{"tag1"},
			toAdd:    []string{"tag1"},
			expected: []string{"tag1"},
		},
		{
			name:     "Empty tags to add leaves list unchanged",
			initial:  []string{"tag1"},
			toAdd:    nil,
			expected: []string{"tag1"},
		},
		{
			name:     "Mix of new and duplicate tags",
			initial:  []string{"host", "env"},
			toAdd:    []string{"env", "region"},
			expected: []string{"host", "env", "region"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			xc := &InputX509Cert{Include: tt.initial}
			xc.updateIncludeTags(tt.toAdd)
			assert.Equal(t, tt.expected, xc.Include)
		})
	}
}
