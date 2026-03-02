package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAppendSinkLabels(t *testing.T) {
	tests := []struct {
		name      string
		m         SinkMap
		labelName string
		lbs       Labels
		expected  SinkMap
	}{
		{
			name:      "Nil map",
			m:         nil,
			labelName: "test",
			lbs:       Labels{"k1": "v1"},
			expected:  nil,
		},
		{
			name:      "Empty name",
			m:         SinkMap{},
			labelName: "",
			lbs:       Labels{"k1": "v1"},
			expected:  SinkMap{},
		},
		{
			name:      "Valid case",
			m:         SinkMap{},
			labelName: "test",
			lbs:       Labels{"k1": "v1"},
			expected:  SinkMap{"test": Labels{"k1": "v1"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AppendSinkLabels(tt.m, tt.labelName, tt.lbs)
			if tt.m != nil {
				assert.Equal(t, tt.expected, tt.m)
			}
		})
	}
}

func TestAppendHostSinkLabels(t *testing.T) {
	tests := []struct {
		name      string
		m         SinkMap
		labelName string
		hs        HostSink
		lbs       Labels
		expected  Labels
	}{
		{
			name:      "HostSink with data",
			m:         SinkMap{},
			labelName: "host1",
			hs: HostSink{
				Host:    "myhost",
				IP:      "1.2.3.4",
				Vendor:  "vendor1",
				OS:      "linux",
				Cluster: "cluster1",
				Server:  "server1",
			},
			lbs: Labels{"custom": "val"},
			expected: Labels{
				"host":    "myhost",
				"ip":      "1.2.3.4",
				"vendor":  "vendor1",
				"os":      "linux",
				"cluster": "cluster1",
				"server":  "server1",
				"custom":  "val",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AppendHostSinkLabels(tt.m, tt.labelName, tt.hs, tt.lbs)
			assert.Equal(t, tt.expected, tt.m[tt.labelName])
		})
	}
}

func TestSinks_Process(t *testing.T) {
	obs := NewObservability(nil, nil)
	ss := NewSinks(obs)

	mockDiscovery := new(MockDiscovery)
	mockDiscovery.On("Name").Return("test-discovery")

	mockSink1 := new(MockSink)
	mockSink1.On("Name").Return("sink1")
	mockSink1.On("Providers").Return([]string{}) // Empty means all
	mockSink1.On("Process", mockDiscovery, mock.Anything).Return()

	ss.Add(mockSink1)
	ss.Add(nil) // Should handle nil safely

	so := new(MockSinkObject)
	ss.Process(mockDiscovery, so)

	mockSink1.AssertCalled(t, "Process", mockDiscovery, so)
}
