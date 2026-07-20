package apikeyauth

import (
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

// desiredCollection returns the canonical schema for the api_keys collection.
// This is the single source of truth for the schema. To evolve the schema,
// only this function needs to change.
func desiredCollection(cfg Config) *core.Collection {
	c := core.NewCollection(core.CollectionTypeBase, cfg.CollectionName, cfg.CollectionID)

	// name: user-defined label for this key (e.g. "My CI Server", "Dev Laptop")
	c.Fields.Add(&core.TextField{
		Name:     "name",
		Required: true,
		Max:      100,
	})

	// key_hash: hex-encoded SHA-256 of the full key (prefix + random)
	c.Fields.Add(&core.TextField{
		Name:     "key_hash",
		Required: true,
		Max:      64, // SHA-256 hex = 64 chars
	})

	// key_prefix: the prefix portion (e.g. "pbk_") — stored for auditing
	c.Fields.Add(&core.TextField{
		Name:     "key_prefix",
		Required: true,
		Max:      8,
	})

	// user: relation to the users collection (the key owner)
	c.Fields.Add(&core.RelationField{
		Name:         "user",
		CollectionId: "_pb_users_auth_",
		MaxSelect:    1,
		Required:     true,
	})

	// disabled: soft-revoke a key without deleting it
	c.Fields.Add(&core.BoolField{
		Name: "disabled",
	})

	// expires_at: optional expiry datetime (nil = never expires)
	c.Fields.Add(&core.DateField{
		Name: "expires_at",
	})

	// Indexes
	c.Indexes = append(c.Indexes,
		// Fast lookup by hash (primary lookup path)
		"CREATE UNIQUE INDEX idx_api_key_hash ON {{NAME}} (key_hash)",
		// Prevent duplicate names per user
		"CREATE UNIQUE INDEX idx_api_key_user_name ON {{NAME}} (user, name)",
	)

	// API Rules — only the owner can access their own keys
	c.ListRule = types.Pointer("user = @request.auth.id")
	c.ViewRule = types.Pointer("user = @request.auth.id")
	c.CreateRule = types.Pointer("user = @request.auth.id")
	c.UpdateRule = types.Pointer("user = @request.auth.id")
	c.DeleteRule = types.Pointer("user = @request.auth.id")

	return c
}

// ensureCollection creates or migrates the collection to match desiredCollection.
func ensureCollection(app core.App, cfg Config) error {
	desired := desiredCollection(cfg)
	existing, err := app.FindCollectionByNameOrId(desired.Name)

	if err != nil {
		// First run — create the collection
		return app.Save(desired)
	}

	// Transplant identity so Save() treats this as an update
	desired.Id = existing.Id
	desired.Created = existing.Created
	desired.MarkAsNotNew() // critical: tells PocketBase this is an UPDATE, not INSERT

	// Avoid expensive no-op save
	if existing.Fields.String() == desired.Fields.String() &&
		existing.Indexes.String() == desired.Indexes.String() {
		return nil
	}

	return app.Save(desired) // SyncRecordTableSchema runs automatically
}
