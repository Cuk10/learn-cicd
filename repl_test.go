package main

import (
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	t.Run("Test case 1: No Authorization header", func(t *testing.T) {
		headers := http.Header{}
		key, err := auth.GetAPIKey(headers)
		if err == auth.ErrNoAuthHeaderIncluded {
			t.Errorf("Expected error %v, got %v", auth.ErrNoAuthHeaderIncluded, err)
		}
		if key != "" {
			t.Errorf("Expected empty API key, got %s", key)
		}
	})

	t.Run("Test case 2: Empty Authorization header", func(t *testing.T) {
		headers := http.Header{"Authorization": []string{""}}
		key, err := auth.GetAPIKey(headers)
		if err != auth.ErrNoAuthHeaderIncluded {
			t.Errorf("Expected error %v, got %v", ErrNoAuthHeaderIncluded, err)
		}
		if key != "" {
			t.Errorf("Expected empty API key, got %s", key)
		}
	})

	t.Run("Test case 3: Malformed Authorization header (Bearer)", func(t *testing.T) {
		headers := http.Header{"Authorization": []string{"Bearer invalid"}}
		key, err := auth.GetAPIKey(headers)
		if err == nil {
			t.Error("Expected error but got nil")
		}
		expectedError := "malformed authorization header"
		if err.Error() != expectedError {
			t.Errorf("Expected error %s, got %s", expectedError, err.Error())
		}
		if key != "" {
			t.Errorf("Expected empty API key, got %s", key)
		}
	})

	t.Run("Test case 4: Malformed Authorization header (missing API key)", func(t *testing.T) {
		headers := http.Header{"Authorization": []string{"ApiKey"}}
		key, err := auth.GetAPIKey(headers)
		if err == nil {
			t.Error("Expected error but got nil")
		}
		expectedError := "malformed authorization header"
		if err.Error() != expectedError {
			t.Errorf("Expected error %s, got %s", expectedError, err.Error())
		}
		if key != "" {
			t.Errorf("Expected empty API key, got %s", key)
		}
	})

	t.Run("Test case 5: Valid Authorization header with API key", func(t *testing.T) {
		headers := http.Header{"Authorization": []string{"ApiKey validkey"}}
		key, err := auth.GetAPIKey(headers)
		if err != nil {
			t.Errorf("Expected no error but got %v", err)
		}
		expectedKey := "validkey"
		if key != expectedKey {
			t.Errorf("Expected API key %s, got %s", expectedKey, key)
		}
	})
}
