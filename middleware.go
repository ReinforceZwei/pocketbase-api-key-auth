package apikeyauth

import (
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pocketbase/pocketbase/tools/types"
)

// apiKeyAuthMiddleware is the global middleware that checks for an API key
// on every request and authenticates the user if a valid key is found.
//
// It runs after PocketBase's built-in JWT auth middleware. If e.Auth is already
// set (by JWT), it does nothing. If no API key header is present, it does nothing.
// Invalid/expired/disabled keys are silently skipped — downstream RequireAuth
// middleware decides whether to return 401.
func apiKeyAuthMiddleware(app core.App, cfg Config) func(e *core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		// Skip if already authenticated by JWT or other means
		if e.Auth != nil {
			return e.Next()
		}

		rawKey := e.Request.Header.Get(cfg.HeaderName)
		if rawKey == "" {
			return e.Next()
		}

		// Quick prefix check to reject obviously invalid keys early
		if !strings.HasPrefix(rawKey, cfg.KeyPrefix) {
			app.Logger().Debug("api key rejected: invalid prefix",
				"prefix", cfg.KeyPrefix)
			return e.Next()
		}

		// Hash the incoming key and look up by hash
		keyHash := security.SHA256(rawKey)
		keyRecord, err := app.FindFirstRecordByData(cfg.CollectionName, "key_hash", keyHash)
		if err != nil {
			app.Logger().Debug("api key not found or invalid", "error", err)
			return e.Next()
		}

		// Check if key is disabled (revoked)
		if keyRecord.GetBool("disabled") {
			app.Logger().Debug("api key is disabled (revoked)",
				"keyId", keyRecord.Id)
			return e.Next()
		}

		// Check expiry
		expiresAt := keyRecord.GetDateTime("expires_at")
		if !expiresAt.IsZero() {
			now, _ := types.ParseDateTime(time.Now())
			if expiresAt.Before(now) {
				app.Logger().Debug("api key has expired",
					"keyId", keyRecord.Id)
				return e.Next()
			}
		}

		// Resolve the associated user
		userId := keyRecord.GetString("user")
		userRecord, err := app.FindRecordById("users", userId)
		if err != nil {
			app.Logger().Debug("api key user not found",
				"error", err, "userId", userId)
			return e.Next()
		}

		e.Auth = userRecord
		return e.Next()
	}
}
