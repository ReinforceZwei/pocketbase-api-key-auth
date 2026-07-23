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
			return e.InternalServerError("apiKeys collection not found", err)
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

// updateAPIKeyHandler handles PATCH /api/api-key/:id (or the configured ApiPath/:id).
//
// Only the following fields may be mutated:
//   - name (user-defined label)
//   - disabled (soft revoke / re-enable)
//   - expires_at (optional expiry)
//
// user, key_hash, and key_prefix are immutable. Any attempt to set them is rejected.
// The authenticated user must own the record.
func updateAPIKeyHandler(app core.App, cfg Config) func(e *core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		recordId := e.Request.PathValue("id")
		if recordId == "" {
			return e.BadRequestError("missing key id", nil)
		}

		record, err := app.FindRecordById(cfg.CollectionName, recordId)
		if err != nil {
			return e.NotFoundError("api key not found", err)
		}

		// Verify ownership — the authenticated user must own this key
		if record.GetString("user") != e.Auth.Id {
			return e.ForbiddenError("you can only update your own API keys", nil)
		}

		// Parse request body into a raw map first so we can reject
		// forbidden fields before applying any mutations.
		var rawBody map[string]interface{}
		if err := e.BindBody(&rawBody); err != nil {
			return e.BadRequestError("invalid request body", err)
		}

		// Reject any attempt to mutate immutable fields
		for key := range rawBody {
			switch key {
			case "user", "key_hash", "key_prefix", "key", "id", "created", "updated":
				return e.BadRequestError(
					fmt.Sprintf("field %q is immutable and cannot be changed", key), nil,
				)
			}
		}

		// Apply allowed fields
		if rawName, ok := rawBody["name"]; ok {
			name, _ := rawName.(string)
			name = strings.TrimSpace(name)
			if name == "" {
				return e.BadRequestError("name cannot be empty", nil)
			}
			record.Set("name", name)
		}

		if rawDisabled, ok := rawBody["disabled"]; ok {
			disabled, ok := rawDisabled.(bool)
			if !ok {
				return e.BadRequestError("disabled must be a boolean", nil)
			}
			record.Set("disabled", disabled)
		}

		if rawExpiresAt, ok := rawBody["expires_at"]; ok {
			expiresStr, _ := rawExpiresAt.(string)
			if expiresStr == "" {
				record.Set("expires_at", nil)
			} else {
				dt, err := types.ParseDateTime(expiresStr)
				if err != nil {
					return e.BadRequestError("invalid expires_at format, use ISO 8601", err)
				}
				record.Set("expires_at", dt)
			}
		}

		if err := app.Save(record); err != nil {
			return e.InternalServerError("failed to update API key", err)
		}

		return e.JSON(http.StatusOK, record.PublicExport())
	}
}

// deleteAPIKeyHandler handles DELETE /api/api-key/:id (or the configured ApiPath/:id).
//
// Only the key owner can delete their own keys.
func deleteAPIKeyHandler(app core.App, cfg Config) func(e *core.RequestEvent) error {
	return func(e *core.RequestEvent) error {
		recordId := e.Request.PathValue("id")
		if recordId == "" {
			return e.BadRequestError("missing key id", nil)
		}

		record, err := app.FindRecordById(cfg.CollectionName, recordId)
		if err != nil {
			return e.NotFoundError("api key not found", err)
		}

		// Verify ownership
		if record.GetString("user") != e.Auth.Id {
			return e.ForbiddenError("you can only delete your own API keys", nil)
		}

		if err := app.Delete(record); err != nil {
			return e.InternalServerError("failed to delete API key", err)
		}

		return e.JSON(http.StatusOK, map[string]string{
			"message": "API key deleted",
		})
	}
}
