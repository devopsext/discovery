package common

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	sreCommon "github.com/devopsext/sre/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUtils_ConvertLabelsMapToSinkMap(t *testing.T) {
	tests := []struct {
		name     string
		input    LabelsMap
		expected SinkMap
	}{
		{
			name:     "Empty map",
			input:    LabelsMap{},
			expected: SinkMap{},
		},
		{
			name: "Single entry",
			input: LabelsMap{
				"obj1": Labels{"k1": "v1"},
			},
			expected: SinkMap{
				"obj1": Labels{"k1": "v1"},
			},
		},
		{
			name: "Multiple entries",
			input: LabelsMap{
				"obj1": Labels{"k1": "v1"},
				"obj2": Labels{"k2": "v2"},
			},
			expected: SinkMap{
				"obj1": Labels{"k1": "v1"},
				"obj2": Labels{"k2": "v2"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertLabelsMapToSinkMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUtils_ConvertSinkMapToLabelsMap(t *testing.T) {
	tests := []struct {
		name     string
		input    SinkMap
		expected LabelsMap
	}{
		{
			name:     "Empty map",
			input:    SinkMap{},
			expected: LabelsMap{},
		},
		{
			name: "Labels values kept, non-Labels skipped",
			input: SinkMap{
				"obj1": Labels{"k1": "v1"},
				"obj2": "not-a-labels-type",
				"obj3": 42,
			},
			expected: LabelsMap{
				"obj1": Labels{"k1": "v1"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertSinkMapToLabelsMap(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUtils_ConvertObjectsToSinkMap(t *testing.T) {
	obj := &Object{Metrics: []string{"up"}}
	tests := []struct {
		name  string
		input Objects
		len   int
	}{
		{
			name:  "Empty",
			input: Objects{},
			len:   0,
		},
		{
			name:  "Single object",
			input: Objects{"svc1": obj},
			len:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertObjectsToSinkMap(tt.input)
			assert.Len(t, result, tt.len)
		})
	}
}

func TestUtils_ConvertSinkMapToObjects(t *testing.T) {
	obj := &Object{Metrics: []string{"up"}}
	tests := []struct {
		name     string
		input    SinkMap
		expected Objects
	}{
		{
			name:     "Empty map",
			input:    SinkMap{},
			expected: Objects{},
		},
		{
			name: "Object values kept, non-Object skipped",
			input: SinkMap{
				"svc1": obj,
				"svc2": "not-an-object",
			},
			expected: Objects{"svc1": obj},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ConvertSinkMapToObjects(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUtils_StringSliceToMap(t *testing.T) {
	tests := []struct {
		name     string
		lines    []string
		expected map[string]string
	}{
		{
			name:     "Key=value pairs",
			lines:    []string{"key1=val1", "key2=val2"},
			expected: map[string]string{"key1": "val1", "key2": "val2"},
		},
		{
			name:     "Key without value",
			lines:    []string{"key1"},
			expected: map[string]string{"key1": ""},
		},
		{
			name:     "Value with embedded equals signs",
			lines:    []string{"key1=val=with=equals"},
			expected: map[string]string{"key1": "val=with=equals"},
		},
		{
			name:     "Empty slice",
			lines:    []string{},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StringSliceToMap(tt.lines)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUtils_ParsePeriodFromNow(t *testing.T) {
	now := time.Unix(1_000_000, 0)

	tests := []struct {
		name      string
		period    string
		wantEmpty bool
	}{
		{
			name:      "Empty period returns empty",
			period:    "",
			wantEmpty: true,
		},
		{
			name:      "Invalid duration returns empty",
			period:    "invalid",
			wantEmpty: true,
		},
		{
			name:      "Negative duration produces past timestamp",
			period:    "-1h",
			wantEmpty: false,
		},
		{
			name:      "Zero hours produces current timestamp",
			period:    "0h",
			wantEmpty: false,
		},
		{
			name:      "Zero days converted to hours",
			period:    "0d",
			wantEmpty: false,
		},
		{
			name:      "Positive duration produces future timestamp",
			period:    "1h",
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePeriodFromNow(tt.period, now)
			if tt.wantEmpty {
				assert.Empty(t, result)
			} else {
				assert.NotEmpty(t, result)
			}
		})
	}
}

func TestUtils_FileWriteWithCheckSum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	data := []byte("hello world")

	t.Run("Write new file without checksum", func(t *testing.T) {
		exists, err := FileWriteWithCheckSum(path, data, false)
		require.NoError(t, err)
		assert.False(t, exists)
		content, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, data, content)
	})

	t.Run("Same checksum skips write and returns exists=true", func(t *testing.T) {
		content := []byte("checksum-content")
		_, err := FileWriteWithCheckSum(path, content, false)
		require.NoError(t, err)
		exists, err := FileWriteWithCheckSum(path, content, true)
		require.NoError(t, err)
		assert.True(t, exists)
	})

	t.Run("Different checksum triggers write", func(t *testing.T) {
		content1 := []byte("first-content")
		_, err := FileWriteWithCheckSum(path, content1, false)
		require.NoError(t, err)
		content2 := []byte("second-content")
		exists, err := FileWriteWithCheckSum(path, content2, true)
		require.NoError(t, err)
		assert.False(t, exists)
	})

	t.Run("Creates parent directories if missing", func(t *testing.T) {
		deepPath := filepath.Join(dir, "a", "b", "c", "file.txt")
		exists, err := FileWriteWithCheckSum(deepPath, data, false)
		require.NoError(t, err)
		assert.False(t, exists)
		assert.FileExists(t, deepPath)
	})
}

func TestUtils_FileMD5(t *testing.T) {
	dir := t.TempDir()

	t.Run("Existing file returns consistent hash", func(t *testing.T) {
		path := filepath.Join(dir, "test.txt")
		data := []byte("hello")
		err := os.WriteFile(path, data, 0600)
		require.NoError(t, err)

		hash := FileMD5(path)
		assert.NotNil(t, hash)

		hashStr := FileMd5ToString(path)
		assert.Equal(t, Md5ToString(data), hashStr)
	})

	t.Run("Non-existent file returns nil", func(t *testing.T) {
		hash := FileMD5("/nonexistent/path/file.txt")
		assert.Nil(t, hash)
	})
}

func TestUtils_SortStringMapByKeys(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]string
		keys     []string
		expected map[string]string
	}{
		{
			name:     "Subset of keys",
			m:        map[string]string{"a": "1", "b": "2", "c": "3"},
			keys:     []string{"c", "a"},
			expected: map[string]string{"a": "1", "c": "3"},
		},
		{
			name:     "All keys",
			m:        map[string]string{"x": "10", "y": "20"},
			keys:     []string{"x", "y"},
			expected: map[string]string{"x": "10", "y": "20"},
		},
		{
			name:     "Empty keys returns empty map",
			m:        map[string]string{"a": "1"},
			keys:     []string{},
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SortStringMapByKeys(tt.m, tt.keys)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestUtils_GetStringKeys(t *testing.T) {
	m := map[string]string{"a": "1", "b": "2", "c": "3"}
	keys := GetStringKeys(m)
	assert.Len(t, keys, 3)
	assert.Contains(t, keys, "a")
	assert.Contains(t, keys, "b")
	assert.Contains(t, keys, "c")
}

func TestUtils_GetLabelsKeys(t *testing.T) {
	m := map[string]Labels{
		"k1": {"a": "1"},
		"k2": {"b": "2"},
	}
	keys := GetLabelsKeys(m)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, "k1")
	assert.Contains(t, keys, "k2")
}

func TestUtils_GetBaseConfigKeys(t *testing.T) {
	m := map[string]*BaseConfig{
		"cfg1": {},
		"cfg2": {},
	}
	keys := GetBaseConfigKeys(m)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, "cfg1")
	assert.Contains(t, keys, "cfg2")
}

func TestUtils_GetFileKeys(t *testing.T) {
	m := map[string]*File{
		"f1": {Path: "/a"},
		"f2": {Path: "/b"},
	}
	keys := GetFileKeys(m)
	assert.Len(t, keys, 2)
	assert.Contains(t, keys, "f1")
	assert.Contains(t, keys, "f2")
}

func TestUtils_ReadJson(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "Valid JSON object",
			input:   []byte(`{"key":"value","num":42}`),
			wantErr: false,
		},
		{
			name:    "Valid JSON array",
			input:   []byte(`[1,2,3]`),
			wantErr: false,
		},
		{
			name:    "Invalid JSON",
			input:   []byte(`{invalid}`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj, err := ReadJson(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, obj)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, obj)
			}
		})
	}
}

func TestUtils_ReadYaml(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "Valid YAML",
			input:   []byte("key: value\nnum: 42\n"),
			wantErr: false,
		},
		{
			name:    "Empty YAML",
			input:   []byte(""),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj, err := ReadYaml(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				_ = obj
			}
		})
	}
}

func TestUtils_ReadToml(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "Valid TOML",
			input:   []byte("[section]\nkey = \"value\"\n"),
			wantErr: false,
		},
		{
			name:    "Invalid TOML",
			input:   []byte("key = "),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj, err := ReadToml(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, obj)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, obj)
			}
		})
	}
}

func TestUtils_ReadFile(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		setup   func() string
		typ     string
		wantErr bool
		wantNil bool
	}{
		{
			name: "Read JSON file by extension",
			setup: func() string {
				path := filepath.Join(dir, "data.json")
				_ = os.WriteFile(path, []byte(`{"key":"value"}`), 0600)
				return path
			},
			wantErr: false,
		},
		{
			name: "Read YAML file by extension",
			setup: func() string {
				path := filepath.Join(dir, "data.yaml")
				_ = os.WriteFile(path, []byte("key: value\n"), 0600)
				return path
			},
			wantErr: false,
		},
		{
			name: "Read TOML file by extension",
			setup: func() string {
				path := filepath.Join(dir, "data.toml")
				_ = os.WriteFile(path, []byte("[section]\nkey = \"value\"\n"), 0600)
				return path
			},
			wantErr: false,
		},
		{
			name: "Read file with explicit type override",
			setup: func() string {
				path := filepath.Join(dir, "data.txt")
				_ = os.WriteFile(path, []byte(`{"key":"value"}`), 0600)
				return path
			},
			typ:     "json",
			wantErr: false,
		},
		{
			name: "Non-existent file returns error",
			setup: func() string {
				return "/nonexistent/path/file.json"
			},
			wantErr: true,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.setup()
			obj, err := ReadFile(path, tt.typ)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, obj)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, obj)
			}
		})
	}
}

func TestUtils_Render(t *testing.T) {
	logger := sreCommon.NewLogs()
	obs := NewObservability(logger, nil)

	tests := []struct {
		name     string
		template string
		obj      any
		expected string
	}{
		{
			name:     "Simple template substitution",
			template: "Hello {{.name}}",
			obj:      map[string]string{"name": "World"},
			expected: "Hello World",
		},
		{
			name:     "Missing key renders with trailing space (no value replaced by empty)",
			template: "Value: {{.missing}}",
			obj:      map[string]string{},
			expected: "Value: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Render(tt.template, tt.obj, obs)
			assert.Equal(t, tt.expected, result)
		})
	}
}
