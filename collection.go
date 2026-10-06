package apikeyauth

import (
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/types"
)

// desiredCollection returns the canonical schema for the apiKeys collection.
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
		Hidden:   true,
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

	// created / updated: autodate fields, so that the built-in API responses
	// carry the same timestamps as any other PocketBase collection.
	c.Fields.Add(&core.AutodateField{
		Name:     "created",
		OnCreate: true,
	})
	c.Fields.Add(&core.AutodateField{
		Name:     "updated",
		OnCreate: true,
		OnUpdate: true,
	})

	// Indexes
	c.Indexes = append(c.Indexes,
		// Fast lookup by hash (primary lookup path)
		"CREATE UNIQUE INDEX idx_api_key_hash ON {{NAME}} (key_hash)",
		// Prevent duplicate names per user
		"CREATE UNIQUE INDEX idx_api_key_user_name ON {{NAME}} (user, name)",
	)

	// API Rules — only the owner can access their own keys.
	//
	// Create and Update are enabled: they are the entry points for the request
	// hooks in hooks.go, which generate the key material, force ownership and
	// reject changes to immutable fields. The rules themselves are one layer of
	// that protection — a create request has to name its own owner to pass.
	c.ListRule = types.Pointer("user = @request.auth.id")
	c.ViewRule = types.Pointer("user = @request.auth.id")
	c.CreateRule = types.Pointer("@request.auth.id != '' && user = @request.auth.id")
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
		existing.Indexes.String() == desired.Indexes.String() &&
		rulesEqual(existing, desired) {
		return nil
	}

	return app.Save(desired) // SyncRecordTableSchema runs automatically
}

// rulesEqual reports whether the API rules of both collections match.
// Rules are part of the plugin's contract (a rule change must be applied on
// upgrade, not only on a field change).
func rulesEqual(a, b *core.Collection) bool {
	return ptrEqual(a.ListRule, b.ListRule) &&
		ptrEqual(a.ViewRule, b.ViewRule) &&
		ptrEqual(a.CreateRule, b.CreateRule) &&
		ptrEqual(a.UpdateRule, b.UpdateRule) &&
		ptrEqual(a.DeleteRule, b.DeleteRule)
}

func ptrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
