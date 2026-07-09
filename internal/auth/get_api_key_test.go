package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr bool
	}{
		{
			name:    "no authorization header",
			headers: http.Header{},
			wantKey: "",
			wantErr: true,
		},
		{
			name: "malformed authorization header - wrong prefix",
			headers: http.Header{
				"Authorization": []string{"Bearer someapikey"},
			},
			wantKey: "",
			wantErr: true,
		},
		{
			name: "malformed authorization header - missing key",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			wantKey: "",
			wantErr: true,
		},
		{
			name: "valid authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey someapikey123"},
			},
			wantKey: "someapikey123",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tc.headers)

			if (err != nil) != tc.wantErr {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if gotKey != tc.wantKey {
				t.Errorf("GetAPIKey() gotKey = %q, want %q", gotKey, tc.wantKey)
			}
		})
	}
}
