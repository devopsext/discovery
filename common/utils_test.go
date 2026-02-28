package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUtils_MergeLabels(t *testing.T) {
	tests := []struct {
		name     string
		labels   []Labels
		expected Labels
	}{
		{
			name:     "Empty",
			labels:   nil,
			expected: Labels{},
		},
		{
			name: "Merge multiple",
			labels: []Labels{
				{"a": "1", "b": "2"},
				{"b": "3", "c": "4"},
			},
			expected: Labels{"a": "1", "b": "2", "c": "4"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, MergeLabels(tt.labels...))
		})
	}
}

func TestUtils_FilterStringMap(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]string
		keys     []string
		expected map[string]string
	}{
		{
			name:     "No keys (returns all)",
			m:        map[string]string{"a": "1", "b": "2"},
			keys:     nil,
			expected: map[string]string{"a": "1", "b": "2"},
		},
		{
			name:     "With keys",
			m:        map[string]string{"a": "1", "b": "2", "c": "3"},
			keys:     []string{"a", "c"},
			expected: map[string]string{"a": "1", "c": "3"},
		},
		{
			name:     "Key not found",
			m:        map[string]string{"a": "1"},
			keys:     []string{"b"},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, FilterStringMap(tt.m, tt.keys))
		})
	}
}

func TestUtils_MergeStringMaps(t *testing.T) {
	tests := []struct {
		name     string
		mm       []map[string]string
		expected map[string]string
	}{
		{
			name:     "Single map",
			mm:       []map[string]string{{"a": "1"}},
			expected: map[string]string{"a": "1"},
		},
		{
			name:     "Multiple maps",
			mm:       []map[string]string{{"a": "1"}, {"b": "2"}, {"a": "3"}},
			expected: map[string]string{"a": "3", "b": "2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, MergeStringMaps(tt.mm...))
		})
	}
}

func TestUtils_Md5(t *testing.T) {
	data := []byte("test")
	expected := "098f6bcd4621d373cade4e832627b4f6"
	assert.Equal(t, expected, Md5ToString(data))
	assert.NotEmpty(t, Md5(data))
}

func TestUtils_RemoveEmptyStrings(t *testing.T) {
	tests := []struct {
		name     string
		items    []string
		expected []string
	}{
		{
			name:     "Mixed",
			items:    []string{"a", "", "b", " ", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "All empty",
			items:    []string{"", ""},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, RemoveEmptyStrings(tt.items))
		})
	}
}

func TestUtils_ReplaceLabelKeys(t *testing.T) {
	labels := map[string]string{"old_key": "value", "keep": "this"}
	replacements := map[string]string{"old_key": "new_key"}
	expected := map[string]string{"new_key": "value", "keep": "this"}
	assert.Equal(t, expected, ReplaceLabelKeys(labels, replacements))
}

func TestUtils_ReplaceLabelValues(t *testing.T) {
	labels := map[string]string{"key": "old_value", "keep": "this"}
	replacements := map[string]string{"old_value": "new_value"}
	expected := map[string]string{"key": "new_value", "keep": "this"}
	assert.Equal(t, expected, ReplaceLabelValues(labels, replacements))
}

func TestUtils_IfDef(t *testing.T) {
	assert.Equal(t, "val", IfDef("val", "def"))
	assert.Equal(t, "def", IfDef(nil, "def"))
	assert.Equal(t, "def", IfDef("", "def"))
	assert.Equal(t, "def", IfDef(0, "def"))
	assert.Equal(t, 1, IfDef(1, "def"))
}

func TestUtils_StringInArr(t *testing.T) {
	assert.True(t, StringInArr("a", []string{"a", "b"}))
	assert.False(t, StringInArr("c", []string{"a", "b"}))
}

func TestUtils_MergeInterfaceMaps(t *testing.T) {
	m1 := map[string]any{"a": 1}
	m2 := map[string]any{"b": "2"}
	expected := map[string]any{"a": 1, "b": "2"}
	assert.Equal(t, expected, MergeInterfacegMaps(m1, m2))
}

func TestUtils_StringContainsAny(t *testing.T) {
	assert.True(t, StringContainsAny("hello", []string{"ell", "world"}))
	assert.False(t, StringContainsAny("hello", []string{"world", "foo"}))
}
