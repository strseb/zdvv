package common

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// LoadEnvFromReader reads from the given io.Reader, parses environment variables,
// and sets them in the process environment.
// It skips empty lines and lines starting with '#'.
// It handles inline comments (text after '#') and variable expansion,
// including ${VAR:-default} syntax.
func LoadEnvFromReader(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)
	// Regex for capturing ${VAR:-DEFAULT} syntax
	defaultPattern := regexp.MustCompile(`\$\{([^:}]+):-([^}]+)\}`)

	for scanner.Scan() {
		lineContent := strings.TrimSpace(scanner.Text())

		// Skip empty lines and full-line comments
		if len(lineContent) == 0 || strings.HasPrefix(lineContent, "#") {
			continue
		}

		// Handle inline comments: take content before the first '#'.
		// This is a simplified approach and assumes '#' for comments is not part of a quoted value
		// or key name. It suits common .env file comment styles.
		effectiveLine := lineContent
		if commentIdx := strings.Index(lineContent, "#"); commentIdx != -1 {
			// Consider if the comment is within quotes - this simple parser does not.
			// For typical .env files like `KEY=VALUE # comment`, this is fine.
			effectiveLine = strings.TrimSpace(lineContent[:commentIdx])
		}

		// If the line becomes empty after stripping a comment (e.g., line was just " # comment")
		if len(effectiveLine) == 0 {
			continue
		}

		parts := strings.SplitN(effectiveLine, "=", 2)
		if len(parts) != 2 {
			// Malformed line (e.g., no '=' or key only after comment stripping), skip it.
			// This aligns with test expectations for "MALFORMED_LINE_NO_EQUALS".
			continue
		}

		key := strings.TrimSpace(parts[0])
		valueStr := strings.TrimSpace(parts[1]) // Raw value part, now without trailing comment

		// Remove surrounding quotes from the value string (single or double)
		if len(valueStr) > 1 {
			if (valueStr[0] == '"' && valueStr[len(valueStr)-1] == '"') ||
				(valueStr[0] == '\'' && valueStr[len(valueStr)-1] == '\'') {
				valueStr = valueStr[1 : len(valueStr)-1]
			}
		}

		// Step 1: Expand variables with defaults, e.g., ${VAR:-default}
		// This custom expansion handles the VAR:-DEFAULT pattern specifically.
		processedValue := defaultPattern.ReplaceAllStringFunc(valueStr, func(match string) string {
			// defaultPattern ensures 3 submatches: full match, varName, defaultValue
			submatches := defaultPattern.FindStringSubmatch(match)
			varName := submatches[1]
			defaultValue := submatches[2]

			if val, ok := os.LookupEnv(varName); ok {
				return val // Use environment variable's value if set (even if empty)
			}
			return defaultValue // Otherwise, use the default value
		})

		// Step 2: Perform standard environment variable expansion (e.g., $VAR or ${VAR})
		// This handles expansions like ${HOME} or $PATH on the potentially modified string.
		finalValue := os.ExpandEnv(processedValue)

		if err := os.Setenv(key, finalValue); err != nil {
			return fmt.Errorf("failed to set environment variable %s: %w", key, err)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading from input: %w", err)
	}
	return nil
}

// ImportDotenv reads a .env file from the current working directory (PWD)
// and adds its key-value pairs to the process environment using LoadEnvFromReader.
func ImportDotenv() error {
	pwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("error getting current working directory: %w", err)
	}

	envFilePath := filepath.Join(pwd, ".env")

	file, err := os.Open(envFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No .env file found, not an error.
		}
		return fmt.Errorf("error opening .env file at %s: %w", envFilePath, err)
	}
	defer file.Close()

	return LoadEnvFromReader(file)
}

// LoadEnvToStruct populates the fields of the given struct pointer
// based on environment variables specified in struct tags.
// The struct tag format is `env:"ENV_VAR_NAME[,default=defaultValue]"`
// or `env:"ENV_VAR_NAME,required"`
// If 'required' is specified and the environment variable is not set,
// an error will be returned.
// If a default value is provided and the environment variable is not set,
// the default value will be used.
func LoadEnvToStruct(ptr interface{}) error {
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Ptr || v.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("input must be a pointer to a struct")
	}

	elem := v.Elem()
	elemType := elem.Type()

	for i := 0; i < elem.NumField(); i++ {
		field := elem.Field(i)
		fieldType := elemType.Field(i)

		if !field.CanSet() {
			continue
		}

		tag := fieldType.Tag.Get("env")
		if tag == "" {
			continue
		}

		parts := strings.Split(tag, ",")
		envVarName := parts[0]
		var defaultValue string
		required := false

		for _, part := range parts[1:] {
			if strings.HasPrefix(part, "default=") {
				defaultValue = strings.TrimPrefix(part, "default=")
			} else if part == "required" {
				required = true
			}
		}

		envValue, found := os.LookupEnv(envVarName)

		if !found {
			if required {
				return fmt.Errorf("required environment variable %s not set", envVarName)
			}
			if defaultValue != "" {
				envValue = defaultValue
			} else {
				// No env var, not required, and no default, so skip
				continue
			}
		}

		switch field.Kind() {
		case reflect.String:
			field.SetString(envValue)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			intValue, err := strconv.ParseInt(envValue, 0, field.Type().Bits())
			if err != nil {
				return fmt.Errorf("error parsing int for %s from %s: %w", fieldType.Name, envValue, err)
			}
			field.SetInt(intValue)
		case reflect.Bool:
			boolValue, err := strconv.ParseBool(envValue)
			if err != nil {
				return fmt.Errorf("error parsing bool for %s from %s: %w", fieldType.Name, envValue, err)
			}
			field.SetBool(boolValue)
		default:
			return fmt.Errorf("unsupported type %s for field %s", field.Kind(), fieldType.Name)
		}
	}
	return nil
}
