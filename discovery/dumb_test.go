package discovery

import (
	"testing"

	"github.com/devopsext/discovery/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Since we need mocks for Discovery and Processor/Sinks, we should reuse what we have.
// However, Dumb itself is a Discovery.

type MockProcessor struct {
	mock.Mock
}

func (m *MockProcessor) Process(d common.Discovery, so common.SinkObject) { m.Called(d, so) }
func (m *MockProcessor) Name() string                                     { return m.Called().String(0) }
func (m *MockProcessor) Providers() []string                              { return m.Called().Get(0).([]string) }

func TestDumb(t *testing.T) {
	obs := common.NewObservability(nil, nil)
	sinks := common.NewSinks(obs)

	tests := []struct {
		name      string
		options   DumbOptions
		setupMock func(m *MockProcessor)
		verify    func(t *testing.T, d *Dumb, m *MockProcessor)
	}{
		{
			name: "Enabled with labels",
			options: DumbOptions{
				Enabled: true,
				LabelsMap: common.LabelsMap{
					"obj1": common.Labels{"l1": "v1"},
				},
			},
			setupMock: func(m *MockProcessor) {
				m.On("Name").Return("mock")
				m.On("Providers").Return([]string{"Dumb"})
				m.On("Process", mock.Anything, mock.Anything).Return()
			},
			verify: func(t *testing.T, d *Dumb, m *MockProcessor) {
				assert.NotNil(t, d)
				assert.Equal(t, "Dumb", d.Name())
				assert.Equal(t, "dumb", d.Source())
				d.Discover()
				m.AssertCalled(t, "Process", d, mock.Anything)
				so := &DumbSinkObject{dumb: d}
				assert.Equal(t, d.options, so.Options())
				assert.NotNil(t, so.Map())
			},
		},
		{
			name:    "Disabled",
			options: DumbOptions{Enabled: false},
			verify: func(t *testing.T, d *Dumb, m *MockProcessor) {
				assert.Nil(t, d)
			},
		},
		{
			name:    "Enabled with default labels",
			options: DumbOptions{Enabled: true},
			setupMock: func(m *MockProcessor) {
				m.On("Name").Return("mock")
				m.On("Providers").Return([]string{"Dumb"})
				m.On("Process", mock.Anything, mock.Anything).Return()
			},
			verify: func(t *testing.T, d *Dumb, m *MockProcessor) {
				assert.NotNil(t, d)
				assert.NotEmpty(t, d.options.LabelsMap)
				d.Discover()
				m.AssertCalled(t, "Process", d, mock.Anything)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockProc := new(MockProcessor)
			if tt.setupMock != nil {
				tt.setupMock(mockProc)
			}

			ps := common.NewProcessors(obs, sinks)
			ps.Add(mockProc)

			d := NewDumb(tt.options, obs, ps)
			if tt.verify != nil {
				tt.verify(t, d, mockProc)
			}
		})
	}
}
