package discovery

import (
	"testing"

	"github.com/devopsext/discovery/common"
	"github.com/stretchr/testify/assert"
)

func TestFileProvider_TryMap(t *testing.T) {
	p := &FileProvider{}

	tests := []struct {
		name     string
		input    any
		expected map[string]any
	}{
		{
			name: "Map input",
			input: map[string]any{
				"key1": "val1",
				"key2": 123,
			},
			expected: map[string]any{
				"key1": "val1",
				"key2": 123,
			},
		},
		{
			name: "Slice of maps",
			input: []any{
				map[string]any{"id": "1", "name": "one"},
				map[string]any{"id": "2", "name": "two"},
			},
			expected: map[string]any{
				"1": map[string]any{"id": "1", "name": "one"},
				"2": map[string]any{"id": "2", "name": "two"},
			},
		},
		{
			name: "Slice of maps without id",
			input: []any{
				map[string]any{"name": "one"},
				map[string]any{"name": "two"},
			},
			expected: map[string]any{
				"one": map[string]any{"name": "one"},
				"two": map[string]any{"name": "two"},
			},
		},
		{
			name:     "Nil input",
			input:    nil,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := p.tryMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFiles_Basic(t *testing.T) {
	obs := common.NewObservability(nil, nil)
	ps := common.NewProcessors(obs, nil)

	t.Run("Empty Config", func(t *testing.T) {
		f := NewFiles(FilesOptions{}, obs, ps)
		assert.Nil(t, f)
	})
}
