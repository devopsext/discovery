package discovery

import (
	"testing"

	"github.com/devopsext/discovery/common"
	toolsVendors "github.com/devopsext/tools/vendors"
	"github.com/stretchr/testify/assert"
)

func TestZabbixHost_Helpers(t *testing.T) {
	tests := []struct {
		name           string
		host           ZabbixHost
		expectedOS     string
		expectedVendor string
		expectedIP     string
		expectedDNS    string
	}{
		{
			name: "Full data",
			host: ZabbixHost{
				Name: "host1",
				Host: "dns1",
				Inventory: map[string]any{
					"os":     "linux",
					"vendor": "dell",
				},
				Interfaces: []*ZabbixHostInterface{
					{IP: "1.2.3.4", Dns: "dns-alt"},
				},
			},
			expectedOS:     "linux",
			expectedVendor: "dell",
			expectedIP:     "1.2.3.4",
			expectedDNS:    "dns-alt",
		},
		{
			name: "Empty inventory and interfaces",
			host: ZabbixHost{
				Name: "host2",
				Host: "dns2",
			},
			expectedOS:     "",
			expectedVendor: "",
			expectedIP:     "",
			expectedDNS:    "",
		},
		{
			name: "Inventory as slice (invalid)",
			host: ZabbixHost{
				Inventory: []any{"something"},
			},
			expectedOS:     "",
			expectedVendor: "",
			expectedIP:     "",
			expectedDNS:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedOS, tt.host.getOS())
			assert.Equal(t, tt.expectedVendor, tt.host.getVendor())
			assert.Equal(t, tt.expectedIP, tt.host.getIP())
			// getHost takes the default host as argument
			if tt.host.Name != "" {
				assert.Equal(t, tt.expectedDNS, tt.host.getHost(tt.host.Host))
			}
		})
	}
}

func TestNewZabbix(t *testing.T) {
	obs := common.NewObservability(nil, nil)
	ps := common.NewProcessors(obs, nil)

	t.Run("Empty URL", func(t *testing.T) {
		z := NewZabbix(ZabbixOptions{}, obs, ps)
		assert.Nil(t, z)
	})

	t.Run("With URL", func(t *testing.T) {
		z := NewZabbix(ZabbixOptions{ZabbixOptions: toolsVendors.ZabbixOptions{URL: "http://localhost"}}, obs, ps)
		assert.NotNil(t, z)
		assert.Equal(t, "Zabbix", z.Name())
		assert.Equal(t, "", z.Source())

		so := &ZabbixSinkObject{zabbix: z}
		assert.Equal(t, z.options, so.Options())
	})
}
