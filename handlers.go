package apikeyauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

// createAPIKeyHandler handles POST /api/api-key (or the configured ApiPath).
//
// Request body (JSON):
//
//	{
//	    "name": "My CI Server",
//	    "expires_at": "2027-01-01T00:00:00Z"   // optional, ISO 8601
//	}
//
// Response (201 Created):
//
//	{
//	    "id": "abc123",
//	    "name": "My CI Server",
//	    "key": "pbk_aB3xK9mW2qR7tY5vN8cL1pF4dG6hJ0sA",  // ← returned ONLY once
//	    "key_prefix": "pbk_",
//	    "user": "user123",
//	    "disabled": false,
//	    "expires_at": "2027-01-01T00:00:00Z",
//	    "created": "2026-07-17T12:00:00Z",
//	    "updated": "2026-07-17T12:00:00Z"
//	}
func createAPIKeyHandler(app core.App, cfg Config) func(e *core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		// Parse request body
		var body struct {
			Name      string `json:"name"`
			ExpiresAt string `json:"expires_at"` // optional, ISO 8601
		}
		if err := e.BindBody(&body); err != nil {
			return e.BadRequestError("invalid request body", err)
		}

		name := strings.TrimSpace(body.Name)
		if name == "" {
			return e.BadRequestError("name is required", nil)
		}

		// Enforce max keys per user limit
		if cfg.MaxKeysPerUser > 0 {
			activeKeys, err := app.FindRecordsByFilter(
				cfg.CollectionName,
				"user = {:userId} && disabled = false",
				"", 0, 0,
				dbx.Params{"userId": e.Auth.Id},
			)
			if err != nil {
				return e.InternalServerError("failed to check key count", err)
			}
			if len(activeKeys) >= cfg.MaxKeysPerUser {
				return e.BadRequestError(
					fmt.Sprintf("maximum of %d active API keys reached", cfg.MaxKeysPerUser),
					nil,
				)
			}
		}

		// Generate the key
		rawKey, keyHash := generateAPIKey(cfg.KeyPrefix, cfg.KeyLength)

		// Find the collection
		collection, err := app.FindCollectionByNameOrId(cfg.CollectionName)
		if err != nil {
			return e.InternalServerError("api_keys collection not found", err)
		}

		// Create the record
		record := core.NewRecord(collection)
		record.Set("name", name)
		record.Set("key_hash", keyHash)
		record.Set("key_prefix", cfg.KeyPrefix)
		record.Set("user", e.Auth.Id)
		record.Set("disabled", false)

		if body.ExpiresAt != "" {
			dt, err := types.ParseDateTime(body.ExpiresAt)
			if err != nil {
				return e.BadRequestError("invalid expires_at format, use ISO 8601", err)
			}
			record.Set("expires_at", dt)
		}

		if err := app.Save(record); err != nil {
			return e.InternalServerError("failed to save API key", err)
		}

		// Return the record WITH the raw key (one-time only)
		result := record.PublicExport()
		result["key"] = rawKey // injected manually — not stored in DB

		return e.JSON(http.StatusCreated, result)
	}
}
