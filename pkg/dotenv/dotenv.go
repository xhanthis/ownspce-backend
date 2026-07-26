// Package dotenv loads KEY=VALUE files for local development. Vercel injects real
// environment variables, so this is never used in production paths.
package dotenv

import (
	"bufio"
	"os"
	"strings"
)

// Load reads a dotenv file, skipping keys already present in the environment so an
// explicit shell variable always wins.
// Args: path (missing file is not an error)
func Load(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, value)
		}
	}
}
