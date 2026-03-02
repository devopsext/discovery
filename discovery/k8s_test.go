package discovery

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractImageNameAndTag(t *testing.T) {
	tests := []struct {
		url          string
		expectedName string
		expectedTag  string
		expectError  bool
	}{
		{
			url:          "nginx:latest",
			expectedName: "nginx",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			url:          "my-registry.io/my-image:v1.2.3",
			expectedName: "my-registry.io/my-image",
			expectedTag:  "v1.2.3",
			expectError:  false,
		},
		{
			url:          "my-registry.io/my-project/my-image:v1.2.3",
			expectedName: "my-registry.io/my-project/my-image",
			expectedTag:  "v1.2.3",
			expectError:  false,
		},
		{
			url:          "my-image",
			expectedName: "my-image",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			url:          "my-registry.io/my-image",
			expectedName: "my-registry.io/my-image",
			expectedTag:  "latest",
			expectError:  false,
		},
		{
			url:         "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			name, tag, err := extractImageNameAndTag(tt.url)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedName, name)
				assert.Equal(t, tt.expectedTag, tag)
			}
		})
	}
}
