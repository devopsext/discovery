package sink

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/devopsext/discovery/common"
	"github.com/devopsext/discovery/discovery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFile_New(t *testing.T) {
	obs := newTestObs()

	tests := []struct {
		name      string
		opts      FileOptions
		wantName  string
		providers []string
	}{
		{
			name:      "Empty options",
			opts:      FileOptions{},
			wantName:  "File",
			providers: []string{},
		},
		{
			name:      "With providers (empty strings removed)",
			opts:      FileOptions{Providers: []string{"PubSub", "", "Consul"}},
			wantName:  "File",
			providers: []string{"PubSub", "Consul"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := NewFile(tt.opts, obs)
			assert.NotNil(t, f)
			assert.Equal(t, tt.wantName, f.Name())
			assert.Equal(t, tt.providers, f.Providers())
		})
	}
}

func TestFile_Process_UnknownDiscovery(t *testing.T) {
	obs := newTestObs()
	f := NewFile(FileOptions{}, obs)

	d := &testDiscovery{name: "Unknown"}
	so := &testSinkObject{m: common.SinkMap{}}

	// Should not panic — logs and returns without processing
	f.Process(d, so)
}

func TestFile_Process_PubSub_WritesFile(t *testing.T) {
	dir := t.TempDir()
	obs := newTestObs()
	f := NewFile(FileOptions{}, obs)

	filePath := filepath.Join(dir, "output.txt")
	pf := &discovery.PubSubMessagePayloadFile{
		Path: filePath,
		Data: []byte("test data"),
	}

	d := &testDiscovery{name: "PubSub"}
	so := &testSinkObject{
		m: common.SinkMap{"file1": pf},
	}

	f.Process(d, so)

	require.FileExists(t, filePath)
	content, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, []byte("test data"), content)
}

func TestFile_Process_PubSub_NonPayloadFileSkipped(t *testing.T) {
	obs := newTestObs()
	f := NewFile(FileOptions{}, obs)

	d := &testDiscovery{name: "PubSub"}
	so := &testSinkObject{
		m: common.SinkMap{
			"notAFile": "just-a-string",
		},
	}

	// Should not panic — non-*PubSubMessagePayloadFile values are skipped
	f.Process(d, so)
}

func TestFile_Process_PubSub_Checksum(t *testing.T) {
	dir := t.TempDir()
	obs := newTestObs()
	f := NewFile(FileOptions{Checksum: true}, obs)

	filePath := filepath.Join(dir, "checksummed.txt")
	data := []byte("stable content")

	// Write twice with same data — second call should see checksum match
	pf := &discovery.PubSubMessagePayloadFile{Path: filePath, Data: data}
	d := &testDiscovery{name: "PubSub"}
	so := &testSinkObject{m: common.SinkMap{"f": pf}}

	f.Process(d, so)
	require.FileExists(t, filePath)

	// Second process with same content — file should still exist and unchanged
	f.Process(d, so)
	content, err := os.ReadFile(filePath)
	require.NoError(t, err)
	assert.Equal(t, data, content)
}