package apikeyauth

import (
	"fmt"
	"strings"

	"github.com/pocketbase/pocketbase/tools/security"
)

// MinKeyLength is the minimum number of random characters required after the prefix.
// Shorter keys are trivially brute-forced or predictable (e.g. a length of 0
// produces a key that is literally just the prefix, which is public knowledge).
const MinKeyLength = 32

// generateAPIKey creates a new API key with the given prefix and random character length.
// Returns the full raw key (prefix + RandomString) and its SHA-256 hash.
// Uses PocketBase's security.RandomString (crypto/rand backed) and security.SHA256.
func generateAPIKey(prefix string, keyLength int) (rawKey string, hash string) {
	rawKey = prefix + security.RandomString(keyLength)
	hash = security.SHA256(rawKey)
	return rawKey, hash
}

// validateKeyPrefix checks that the prefix is valid:
//   - 3–8 characters
//   - alphanumeric + trailing underscore (mandatory)
//   - must end with underscore for readability
func validateKeyPrefix(prefix string) error {
	if len(prefix) < 3 || len(prefix) > 8 {
		return fmt.Errorf("key prefix must be 3–8 characters, got %d", len(prefix))
	}
	if !strings.HasSuffix(prefix, "_") {
		return fmt.Errorf("key prefix must end with '_'")
	}
	// Check alphanumeric + underscore
	for _, r := range strings.TrimSuffix(prefix, "_") {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return fmt.Errorf("key prefix must be alphanumeric, got %q", prefix)
		}
	}
	return nil
}
