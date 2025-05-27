/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package common

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestLoadEnvFromReader(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedEnv map[string]string
		expectError bool
	}{
		{
			name: "valid .env content",
			input: `
KEY1=VALUE1
KEY2=VALUE2 # with comment
# This is a comment
KEY3="quoted value"
KEY4='another quoted value'
EMPTY_KEY=
KEY_WITH_EXPAND=${HOME}/test
KEY_WITH_DEFAULT=${UNDEFINED_VAR:-default_val}
KEY_WITH_EXISTING_ENV=${PATH}
`, // Assuming PATH is set
			expectedEnv: map[string]string{
				"KEY1":                  "VALUE1",
				"KEY2":                  "VALUE2",
				"KEY3":                  "quoted value",
				"KEY4":                  "another quoted value",
				"EMPTY_KEY":             "",
				"KEY_WITH_EXPAND":       os.Getenv("HOME") + "/test",
				"KEY_WITH_DEFAULT":      "default_val",
				"KEY_WITH_EXISTING_ENV": os.Getenv("PATH"),
			},
			expectError: false,
		},
		{
			name:        "empty input",
			input:       "",
			expectedEnv: map[string]string{},
			expectError: false,
		},
		{
			name: "only comments and empty lines",
			input: `
# comment 1

   # comment 2

`,
			expectedEnv: map[string]string{},
			expectError: false,
		},
		{
			name:        "malformed line - no equals",
			input:       "MALFORMED_LINE_NO_EQUALS",
			expectedEnv: map[string]string{}, // Should skip malformed line
			expectError: false,               // Currently skips, does not error
		},
		{
			name:        "malformed line - multiple equals",
			input:       "KEY_MULTI_EQUALS=VAL1=VAL2",
			expectedEnv: map[string]string{"KEY_MULTI_EQUALS": "VAL1=VAL2"}, // SplitN behavior
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Store original env values to restore them later
			originalEnv := make(map[string]string)
			for key := range tt.expectedEnv {
				if val, ok := os.LookupEnv(key); ok {
					originalEnv[key] = val
				}
				// Ensure keys are unset before the test if they are expected
				os.Unsetenv(key)
			}
			// Special case for KEY_WITH_EXISTING_ENV, ensure it's not cleared if it's PATH or similar
			if _, ok := tt.expectedEnv["KEY_WITH_EXISTING_ENV"]; !ok {
				if val, ok_path := os.LookupEnv("PATH"); ok_path {
					originalEnv["PATH"] = val // Store PATH if it was set
				}
			}

			defer func() {
				// Restore original environment variables
				for key, val := range originalEnv {
					os.Setenv(key, val)
				}
				// Clear variables set by the test if they weren't originally set
				for key := range tt.expectedEnv {
					if _, ok := originalEnv[key]; !ok {
						os.Unsetenv(key)
					}
				}
			}()

			reader := strings.NewReader(tt.input)
			err := LoadEnvFromReader(reader)

			if (err != nil) != tt.expectError {
				t.Errorf("LoadEnvFromReader() error = %v, expectError %v", err, tt.expectError)
				return
			}

			for key, expectedValue := range tt.expectedEnv {
				actualValue, found := os.LookupEnv(key)
				if !found {
					t.Errorf("Expected env variable %s to be set, but it was not", key)
					continue
				}
				if actualValue != expectedValue {
					t.Errorf("Env variable %s: expected \"%s\", got \"%s\"", key, expectedValue, actualValue)
				}
			}
		})
	}
}

func TestLoadEnvToStruct(t *testing.T) {
	type Config struct {
		Host        string `env:"TEST_HOST,default=localhost"`
		Port        int    `env:"TEST_PORT,required"`
		Debug       bool   `env:"TEST_DEBUG,default=false"`
		APIKey      string `env:"TEST_API_KEY"`
		Timeout     int64  `env:"TEST_TIMEOUT,default=5000"`
		NotUsed     string
		Temperature float64 `env:"TEST_TEMPERATURE,default=23.5"`
		Latitude    float64 `env:"TEST_LATITUDE"`
	}

	type ConfigRequiredOnly struct {
		Name string `env:"TEST_NAME,required"`
	}

	type ConfigBadType struct {
		BadInt int `env:"TEST_BAD_INT"`
	}

	type ConfigFloat32 struct {
		Value float32 `env:"TEST_FLOAT32,default=3.14"`
	}

	tests := []struct {
		name         string
		setupEnv     func() // Function to set up environment variables for the test
		tearDownEnv  func() // Function to clean up environment variables after the test
		targetStruct interface{}
		expectError  bool
		validate     func(t *testing.T, cfg interface{}) // Optional validation function
	}{
		{
			name: "all fields populated",
			setupEnv: func() {
				os.Setenv("TEST_HOST", "testhost.com")
				os.Setenv("TEST_PORT", "8080")
				os.Setenv("TEST_DEBUG", "true")
				os.Setenv("TEST_API_KEY", "secret")
				os.Setenv("TEST_TIMEOUT", "1000")
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_HOST")
				os.Unsetenv("TEST_PORT")
				os.Unsetenv("TEST_DEBUG")
				os.Unsetenv("TEST_API_KEY")
				os.Unsetenv("TEST_TIMEOUT")
			},
			targetStruct: &Config{},
			expectError:  false,
			validate: func(t *testing.T, s interface{}) {
				cfg := s.(*Config)
				if cfg.Host != "testhost.com" || cfg.Port != 8080 || !cfg.Debug || cfg.APIKey != "secret" || cfg.Timeout != 1000 {
					t.Errorf("Expected specific values, got %+v", *cfg)
				}
			},
		},
		{
			name: "default values used",
			setupEnv: func() {
				os.Setenv("TEST_PORT", "9090") // Only required field
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_PORT")
			},
			targetStruct: &Config{},
			expectError:  false,
			validate: func(t *testing.T, s interface{}) {
				cfg := s.(*Config)
				if cfg.Host != "localhost" || cfg.Port != 9090 || cfg.Debug != false || cfg.APIKey != "" || cfg.Timeout != 5000 {
					t.Errorf("Expected default values, got %+v", *cfg)
				}
			},
		},
		{
			name: "required field missing",
			setupEnv: func() {
				// TEST_PORT is missing
				os.Setenv("TEST_HOST", "somehost")
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_HOST")
			},
			targetStruct: &Config{},
			expectError:  true,
		},
		{
			name: "required field present",
			setupEnv: func() {
				os.Setenv("TEST_NAME", "appname")
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_NAME")
			},
			targetStruct: &ConfigRequiredOnly{},
			expectError:  false,
			validate: func(t *testing.T, s interface{}) {
				cfg := s.(*ConfigRequiredOnly)
				if cfg.Name != "appname" {
					t.Errorf("Expected Name to be 'appname', got '%s'", cfg.Name)
				}
			},
		},
		{
			name:         "input not a pointer",
			targetStruct: Config{},
			expectError:  true,
		},
		{
			name:         "input pointer to non-struct",
			targetStruct: new(int),
			expectError:  true,
		},
		{
			name: "valid float values",
			setupEnv: func() {
				os.Setenv("TEST_PORT", "123") // To satisfy required
				os.Setenv("TEST_TEMPERATURE", "25.75")
				os.Setenv("TEST_LATITUDE", "-33.8651")
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_PORT")
				os.Unsetenv("TEST_TEMPERATURE")
				os.Unsetenv("TEST_LATITUDE")
			},
			targetStruct: &Config{},
			expectError:  false,
			validate: func(t *testing.T, s interface{}) {
				cfg := s.(*Config)
				if cfg.Temperature != 25.75 || cfg.Latitude != -33.8651 {
					t.Errorf("Expected Temperature=25.75 and Latitude=-33.8651, got %f and %f",
						cfg.Temperature, cfg.Latitude)
				}
			},
		},
		{
			name: "malformed int value",
			setupEnv: func() {
				os.Setenv("TEST_BAD_INT", "not-an-int")
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_BAD_INT")
			},
			targetStruct: &ConfigBadType{},
			expectError:  true,
		},
		{
			name: "empty env var for string",
			setupEnv: func() {
				os.Setenv("TEST_PORT", "123") // required
				os.Setenv("TEST_API_KEY", "")
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_PORT")
				os.Unsetenv("TEST_API_KEY")
			},
			targetStruct: &Config{},
			expectError:  false,
			validate: func(t *testing.T, s interface{}) {
				cfg := s.(*Config)
				if cfg.APIKey != "" {
					t.Errorf("Expected APIKey to be empty string, got '%s'", cfg.APIKey)
				}
			},
		},
		{
			name: "float default values",
			setupEnv: func() {
				os.Setenv("TEST_PORT", "123") // required
				// TEST_TEMPERATURE not set, should use default
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_PORT")
			},
			targetStruct: &Config{},
			expectError:  false,
			validate: func(t *testing.T, s interface{}) {
				cfg := s.(*Config)
				if cfg.Temperature != 23.5 {
					t.Errorf("Expected Temperature=23.5 (default), got %f", cfg.Temperature)
				}
			},
		},
		{
			name: "invalid float value",
			setupEnv: func() {
				os.Setenv("TEST_PORT", "123") // required
				os.Setenv("TEST_TEMPERATURE", "not-a-float")
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_PORT")
				os.Unsetenv("TEST_TEMPERATURE")
			},
			targetStruct: &Config{},
			expectError:  true,
		},
		{
			name: "scientific notation float",
			setupEnv: func() {
				os.Setenv("TEST_PORT", "123")           // required
				os.Setenv("TEST_TEMPERATURE", "1.23e2") // 123.0
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_PORT")
				os.Unsetenv("TEST_TEMPERATURE")
			},
			targetStruct: &Config{},
			expectError:  false,
			validate: func(t *testing.T, s interface{}) {
				cfg := s.(*Config)
				if cfg.Temperature != 123.0 {
					t.Errorf("Expected Temperature=123.0, got %f", cfg.Temperature)
				}
			},
		},
		{
			name: "float32 support",
			setupEnv: func() {
				os.Setenv("TEST_FLOAT32", "2.71828")
			},
			tearDownEnv: func() {
				os.Unsetenv("TEST_FLOAT32")
			},
			targetStruct: &ConfigFloat32{},
			expectError:  false,
			validate: func(t *testing.T, s interface{}) {
				cfg := s.(*ConfigFloat32)
				// Using delta comparison since float32 has precision issues
				delta := float32(0.00001)
				expected := float32(2.71828)
				if cfg.Value < expected-delta || cfg.Value > expected+delta {
					t.Errorf("Expected Value≈2.71828, got %f", cfg.Value)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupEnv != nil {
				tt.setupEnv()
			}
			if tt.tearDownEnv != nil {
				defer tt.tearDownEnv()
			}

			// For tests that modify a struct, create a fresh instance each time
			var target interface{}
			if tt.targetStruct != nil {
				// If it's a pointer, we need to dereference its type to make a new one, then take address
				val := reflect.ValueOf(tt.targetStruct)
				if val.Kind() == reflect.Ptr {
					target = reflect.New(val.Type().Elem()).Interface()
				} else {
					target = tt.targetStruct // For non-pointer error cases
				}
			}

			err := LoadEnvToStruct(target)

			if (err != nil) != tt.expectError {
				t.Errorf("LoadEnvToStruct() error = %v, expectError %v", err, tt.expectError)
				return
			}

			if err == nil && tt.validate != nil {
				tt.validate(t, target)
			}
		})
	}
}
