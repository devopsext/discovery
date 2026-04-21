package sink

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/devopsext/discovery/common"
	"github.com/stretchr/testify/assert"
)

func TestJson_New(t *testing.T) {
	obs := newTestObs()
	options := JsonOptions{
		Dir: t.TempDir(),
	}

	j := NewJson(options, obs)
	assert.NotNil(t, j)
	assert.Equal(t, "Json", j.Name())
}

func TestJson_New_EmptyDir(t *testing.T) {
	obs := newTestObs()
	options := JsonOptions{
		Dir: "",
	}

	j := NewJson(options, obs)
	assert.Nil(t, j)
}

func TestJson_Process(t *testing.T) {
	obs := newTestObs()
	dir := t.TempDir()
	options := JsonOptions{
		Dir: dir,
	}

	j := NewJson(options, obs)
	assert.NotNil(t, j)

	discovery := &testDiscovery{name: "test-discovery"}
	sinkObject := &testSinkObject{
		m: common.SinkMap{
			"key": "value",
		},
	}

	j.Process(discovery, sinkObject)

	filePath := filepath.Join(dir, "test-discovery.json")
	assert.FileExists(t, filePath)

	data, err := os.ReadFile(filePath)
	assert.NoError(t, err)
	assert.Contains(t, string(data), `"key":"value"`)
}
