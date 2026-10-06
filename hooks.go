package apikeyauth

import (
	"fmt"
	"strings"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
	"github.com/spf13/cast"
)

// immutableFields lists the fields a client may never modify after creation.
//
// "key" is not a real column: it is the one-time plaintext value attached to the
// create response, and it is rejected here as well so that it cannot be used to
// smuggle data into an update.
var immutableFields = []string{
	"id", "created", "updated",
	"user", "key_hash", "key_prefix", "key",
}

// serverOwnedFields are re-applied from the stored record on every update, so
// that a request which slips past the immutability check above still cannot
// reassign an existing key.
//
// Note that key_hash does not strictly need this guard: it is a hidden field, so
// PocketBase drops it from the submitted data and restores the stored value for
// non-superusers before this hook even runs.
var serverOwnedFields = []string{"user", "key_prefix", "key_hash"}

// registerRequestHooks replaces what used to be the custom CRUD endpoints.
//
// PocketBase's built-in Record API requests are intercepted with the designated
// request hooks, which run after the request body has been loaded into
// e.Record but *before* the record is validated and saved. Mutating e.Record and
// then calling e.Next() therefore behaves exactly like the old handlers, while
// letting clients use the standard REST API and JS SDK.
func registerRequestHooks(app core.App, cfg Config) {
	// Collection events are tagged with [collection.Id, collection.Name]. One
	// TaggedHook registered with both tags still runs only once; passing the ID
	// as well keeps the hooks working if the collection is renamed.
	tags := []string{cfg.CollectionName, cfg.CollectionID}

	// ---------------------------------------------------------------------
	// Create — replaces POST /api/api-key
	// ---------------------------------------------------------------------
	app.OnRecordCreateRequest(tags...).BindFunc(func(e *core.RecordRequestEvent) error {
		body, err := requestBody(e)
		if err != nil {
			return e.BadRequestError("invalid request body", err)
		}

		rawKey, keyHash := generateAPIKey(cfg.KeyPrefix, cfg.KeyLength)

		// Fields owned by the server: whatever the client submitted is
		// discarded and replaced here.
		e.Record.Set("key_hash", keyHash)
		e.Record.Set("key_prefix", cfg.KeyPrefix)
		e.Record.Set("disabled", false)
		trimName(e.Record)

		// A key always belongs to its creator. Superusers may create keys on
		// behalf of another user by submitting an explicit "user" value.
		if e.Auth != nil && !e.Auth.IsSuperuser() {
			e.Record.Set("user", e.Auth.Id)
		}

		ownerId := e.Record.GetString("user")
		if ownerId == "" {
			return e.BadRequestError("user is required", nil)
		}

		if err := validateExpiresAt(e, body); err != nil {
			return err
		}

		if cfg.MaxKeysPerUser > 0 {
			activeKeys, err := e.App.FindRecordsByFilter(
				cfg.CollectionName,
				"user = {:userId} && disabled = false",
				"", 0, 0,
				dbx.Params{"userId": ownerId},
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

		// The raw key is attached as custom record data: PublicExport() includes
		// it in this response, while DBExport() (and therefore the INSERT) never
		// contains it. There is no second chance to read the key.
		e.Record.WithCustomData(true)
		e.Record.Set("key", rawKey)

		return e.Next()
	})

	// ---------------------------------------------------------------------
	// Update — replaces PATCH /api/api-key/:id
	// ---------------------------------------------------------------------
	app.OnRecordUpdateRequest(tags...).BindFunc(func(e *core.RecordRequestEvent) error {
		body, err := requestBody(e)
		if err != nil {
			return e.BadRequestError("invalid request body", err)
		}

		for _, field := range immutableFields {
			if _, ok := body[field]; ok {
				return e.BadRequestError(
					fmt.Sprintf("field %q is immutable and cannot be changed", field),
					nil,
				)
			}
		}

		if err := validateExpiresAt(e, body); err != nil {
			return err
		}

		// Restore the server owned values from the stored record. Without this a
		// client could hand its key over to another user through "user", or
		// change the "key_prefix" used for auditing.
		original := e.Record.Original()
		for _, field := range serverOwnedFields {
			if value, ok := original.GetRaw(field).(string); ok {
				e.Record.Set(field, value)
			}
		}
		trimName(e.Record)

		return e.Next()
	})

	// Delete needs no hook: the collection's DeleteRule
	// ("user = @request.auth.id") already restricts deletion to the key owner.
}

// requestBody re-reads the raw submitted request body.
//
// It must be used instead of RequestInfo().Body, which holds the *normalized*
// values: by the time a request hook runs, an unparseable date has already been
// replaced with an empty value there, and hidden fields have been filtered out.
//
// The router wraps the request body in a rereadable reader, so calling BindBody
// again after PocketBase has consumed the body is safe.
func requestBody(e *core.RecordRequestEvent) (map[string]any, error) {
	body := map[string]any{}
	if err := e.BindBody(&body); err != nil {
		return nil, err
	}

	return body, nil
}

// trimName normalizes the user supplied label, mirroring the old handlers.
// An empty name is left untouched so that the required-field validation of the
// collection reports it.
func trimName(record *core.Record) {
	if name := strings.TrimSpace(record.GetString("name")); name != "" {
		record.Set("name", name)
	}
}

// validateExpiresAt rejects unparseable expires_at values.
//
// PocketBase's date field is deliberately lenient: [types.ParseDateTime] never
// fails, it falls back to the zero time, and a zero date means "never expires".
// Accepting that would silently turn a typo into a key that never expires, so
// the raw value has to be checked here.
//
// An empty or absent value is allowed — it means "no expiry".
func validateExpiresAt(e *core.RecordRequestEvent, body map[string]any) error {
	raw, ok := body["expires_at"]
	if !ok {
		return nil
	}

	value := strings.TrimSpace(cast.ToString(raw))
	if value == "" {
		return nil
	}

	if dt, err := types.ParseDateTime(value); err != nil || dt.IsZero() {
		return e.BadRequestError("invalid expires_at format, use ISO 8601", nil)
	}

	return nil
}
