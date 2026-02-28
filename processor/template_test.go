package processor

import (
	"testing"

	"github.com/devopsext/discovery/common"
	sreCommon "github.com/devopsext/sre/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type mockDiscovery struct {
	mock.Mock
}

func (m *mockDiscovery) Discover()      { m.Called() }
func (m *mockDiscovery) Name() string   { return m.Called().String(0) }
func (m *mockDiscovery) Source() string { return m.Called().String(0) }

type mockSinkObject struct {
	mock.Mock
}

func (m *mockSinkObject) Map() common.SinkMap { return m.Called().Get(0).(common.SinkMap) }
func (m *mockSinkObject) Options() any        { return m.Called().Get(0) }

func newTestObs() *common.Observability {
	return common.NewObservability(sreCommon.NewLogs(), nil)
}

func TestNewTemplate(t *testing.T) {
	tests := []struct {
		name      string
		opts      TemplateOptions
		wantNil   bool
		wantName  string
		providers []string
	}{
		{
			name:    "Empty content returns nil",
			opts:    TemplateOptions{Content: ""},
			wantNil: true,
		},
		{
			name:     "Valid content returns Template",
			opts:     TemplateOptions{Content: "{{.name}}"},
			wantNil:  false,
			wantName: "Template",
		},
		{
			name: "With providers (empty strings removed)",
			opts: TemplateOptions{
				Content:   "{{.name}}",
				Providers: []string{"provider1", "", "provider2"},
			},
			wantNil:   false,
			providers: []string{"provider1", "provider2"},
		},
		{
			name:      "No providers returns empty slice",
			opts:      TemplateOptions{Content: "hello"},
			wantNil:   false,
			providers: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := newTestObs()
			tpl := NewTemplate(tt.opts, obs, nil)
			if tt.wantNil {
				assert.Nil(t, tpl)
				return
			}
			assert.NotNil(t, tpl)
			if tt.wantName != "" {
				assert.Equal(t, tt.wantName, tpl.Name())
			}
			if tt.providers != nil {
				assert.Equal(t, tt.providers, tpl.Providers())
			}
		})
	}
}

func TestTemplate_Process(t *testing.T) {
	obs := newTestObs()
	tpl := NewTemplate(TemplateOptions{Content: "{{.name}}"}, obs, nil)
	assert.NotNil(t, tpl)

	d := &mockDiscovery{}
	d.On("Name").Return("test-discovery")

	so := &mockSinkObject{}
	so.On("Map").Return(common.SinkMap{"key": "value"})

	// Should not panic or error
	tpl.Process(d, so)
	d.AssertCalled(t, "Name")
}

func TestTemplateSetCommonLabelValue(t *testing.T) {
	tests := []struct {
		name   string
		labels common.Labels
		key    string
		value  string
		want   string
	}{
		{
			name:   "Sets value in non-nil labels",
			labels: common.Labels{},
			key:    "env",
			value:  "prod",
			want:   "prod",
		},
		{
			name:   "Overwrites existing value",
			labels: common.Labels{"env": "dev"},
			key:    "env",
			value:  "prod",
			want:   "prod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := templateSetCommonLabelValue(tt.labels, tt.key, tt.value)
			assert.Empty(t, result) // always returns ""
			assert.Equal(t, tt.want, tt.labels[tt.key])
		})
	}
}

func TestTemplateSetCommonLabelValue_NilLabels(t *testing.T) {
	result := templateSetCommonLabelValue(nil, "key", "value")
	assert.Empty(t, result)
}

func TestTemplateGetCommonLabelValue(t *testing.T) {
	tests := []struct {
		name   string
		labels common.Labels
		key    string
		want   string
	}{
		{
			name:   "Existing key returns value",
			labels: common.Labels{"region": "us-east-1"},
			key:    "region",
			want:   "us-east-1",
		},
		{
			name:   "Missing key returns empty",
			labels: common.Labels{"other": "val"},
			key:    "missing",
			want:   "",
		},
		{
			name:   "Nil labels returns empty",
			labels: nil,
			key:    "any",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := templateGetCommonLabelValue(tt.labels, tt.key)
			assert.Equal(t, tt.want, result)
		})
	}
}
