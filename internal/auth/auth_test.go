package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name: "Valid Authorization Header",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			expectedKey:   "abc1234",
			expectedError: nil,
		},
		{
			name: "No Authorization Header",
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization Header",
			headers: http.Header{
				"Authorization": []string{"Bearer xyz789"},
			},
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := GetAPIKey(test.headers)
			if key != test.expectedKey {
				t.Errorf("Expected key: %s, got: %s", test.expectedKey, key)
			}
			if !reflect.DeepEqual(err, test.expectedError) {
				t.Errorf("Expected error: %v, got: %v", test.expectedError, err)
			}
		})
	}
}
