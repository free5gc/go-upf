package forwarder

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckGtp5gVersion(t *testing.T) {
	for _, tt := range []struct {
		name    string
		version string
		wantErr string
	}{
		{name: "minimum", version: "0.9.3"},
		{name: "previous release", version: "0.10.2"},
		{name: "maximum", version: "0.10.3"},
		{
			name:    "below minimum",
			version: "0.9.2",
			wantErr: "gtp5g version(0.9.2) should be 0.9.3 <= version <= 0.10.3",
		},
		{
			name:    "above maximum",
			version: "0.10.4",
			wantErr: "gtp5g version(0.10.4) should be 0.9.3 <= version <= 0.10.3",
		},
		{
			name:    "future minor release",
			version: "0.11.0",
			wantErr: "gtp5g version(0.11.0) should be 0.9.3 <= version <= 0.10.3",
		},
		{
			name:    "invalid version",
			version: "invalid",
			wantErr: "Unable to parse gtp5g version(invalid)",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := checkGtp5gVersion(tt.version)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
