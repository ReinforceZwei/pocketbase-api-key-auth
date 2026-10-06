package apikeyauth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tests"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/pocketbase/pocketbase/tools/types"
)

// Pre-seeded test user from the test database (test@example.com).
const testUserId = "4q1xlclmfloku33"

// Valid JWT token for the pre-seeded test user.
const testUserToken = "eyJhbGciOiJIUzI1NiJ9.eyJpZCI6IjRxMXhsY2xtZmxva3UzMyIsInR5cGUiOiJhdXRoIiwiY29sbGVjdGlvbklkIjoiX3BiX3VzZXJzX2F1dGhfIiwiZXhwIjoyNTI0NjA0NDYxLCJyZWZyZXNoYWJsZSI6dHJ1ZX0.ZT3F0Z3iM-xbGgSG3LEKiEzHrPHr8t8IuHLZGGNuxLo"

// =============================================================================
// Unit Tests — No App Required
// =============================================================================

func TestGenerateAPIKey(t *testing.T) {
	t.Parallel()

	prefix := "pbk_"
	rawKey, hash := generateAPIKey(prefix, 43)

	// Verify prefix
	if !strings.HasPrefix(rawKey, prefix) {
		t.Errorf("expected key to start with %q, got %q", prefix, rawKey)
	}

	// Verify length (prefix + 43 random chars)
	if len(rawKey) != len(prefix)+43 {
		t.Errorf("expected key length %d, got %d", len(prefix)+43, len(rawKey))
	}

	// Verify hash
	expectedHash := security.SHA256(rawKey)
	if hash != expectedHash {
		t.Errorf("hash mismatch: got %q, expected %q", hash, expectedHash)
	}

	// Two keys should be different
	rawKey2, hash2 := generateAPIKey(prefix, 43)
	if rawKey == rawKey2 {
		t.Error("consecutive generated keys should be different")
	}
	if hash == hash2 {
		t.Error("hashes of different keys should be different")
	}
}

func TestGenerateAPIKeyEmptyPrefix(t *testing.T) {
	t.Parallel()

	prefix := ""
	rawKey, hash := generateAPIKey(prefix, 20)

	if len(rawKey) != 20 {
		t.Errorf("expected key length %d, got %d", 20, len(rawKey))
	}
	if hash == "" {
		t.Error("hash should not be empty")
	}
	if !strings.HasPrefix(rawKey, prefix) {
		t.Errorf("expected key to start with empty prefix, got %q", rawKey)
	}
}

func TestGenerateAPIKeyZeroLength(t *testing.T) {
	t.Parallel()

	prefix := "app_"
	rawKey, hash := generateAPIKey(prefix, 0)

	if rawKey != prefix {
		t.Errorf("expected key to be just prefix %q, got %q", prefix, rawKey)
	}
	expectedHash := security.SHA256(prefix)
	if hash != expectedHash {
		t.Errorf("hash mismatch: got %q, expected %q", hash, expectedHash)
	}
}

func TestValidateKeyPrefix_Valid(t *testing.T) {
	t.Parallel()

	validPrefixes := []string{
		"pbk_", "app_", "my_", "abc_",
		"A1b_", "Test_", "K3y_", "xyz_",
	}

	for _, p := range validPrefixes {
		if err := validateKeyPrefix(p); err != nil {
			t.Errorf("expected valid prefix %q, got error: %v", p, err)
		}
	}
}

func TestValidateKeyPrefix_Invalid(t *testing.T) {
	t.Parallel()

	invalidPrefixes := []string{
		"ab",         // too short (2 chars, no underscore)
		"a_",         // too short (2 chars total)
		"toooooLong", // too long, no underscore
		"toolong__",  // too long (8 chars + underscore)
		"plain",      // no underscore
		"abc-def_",   // hyphen not allowed
		"abc def_",   // space not allowed
		"abc!_",      // special char not allowed
		"_",          // only underscore
		"__",         // only underscores
	}

	for _, p := range invalidPrefixes {
		if err := validateKeyPrefix(p); err == nil {
			t.Errorf("expected invalid prefix %q, but no error returned", p)
		}
	}
}

func TestDesiredCollection(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	c := desiredCollection(cfg)

	// Name and ID
	if c.Name != cfg.CollectionName {
		t.Errorf("expected collection name %q, got %q", cfg.CollectionName, c.Name)
	}

	// Field count
	fieldNames := make([]string, len(c.Fields))
	for i, f := range c.Fields {
		fieldNames[i] = f.GetName()
	}

	expectedFields := []string{"name", "key_hash", "key_prefix", "user", "disabled", "expires_at", "created", "updated"}
	// Field count: 8 custom fields + 1 auto system field (id) = 9
	if len(c.Fields) != 9 {
		t.Errorf("expected 9 fields (8 custom + id), got %d", len(c.Fields))
	}

	for _, name := range expectedFields {
		f := c.Fields.GetByName(name)
		if f == nil {
			t.Errorf("expected field %q not found", name)
		}
	}

	// Indexes
	if len(c.Indexes) != 2 {
		t.Errorf("expected 2 indexes, got %d", len(c.Indexes))
	}

	// API Rules — every operation is scoped to the key owner. Create and Update
	// are the entry points for the request hooks (see hooks.go).
	const ownerRule = "user = @request.auth.id"
	if c.ListRule == nil || *c.ListRule != ownerRule {
		t.Error("ListRule not set correctly")
	}
	if c.ViewRule == nil || *c.ViewRule != ownerRule {
		t.Error("ViewRule not set correctly")
	}
	if c.CreateRule == nil || *c.CreateRule != "@request.auth.id != '' && "+ownerRule {
		t.Error("CreateRule not set correctly")
	}
	if c.UpdateRule == nil || *c.UpdateRule != ownerRule {
		t.Error("UpdateRule not set correctly")
	}
	if c.DeleteRule == nil || *c.DeleteRule != ownerRule {
		t.Error("DeleteRule not set correctly")
	}
}

func TestDesiredCollectionCustomName(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.CollectionName = "my_custom_keys"
	c := desiredCollection(cfg)

	if c.Name != "my_custom_keys" {
		t.Errorf("expected collection name %q, got %q", "my_custom_keys", c.Name)
	}
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	if cfg.CollectionName != "apiKeys" {
		t.Errorf("expected CollectionName 'apiKeys', got %q", cfg.CollectionName)
	}
	if cfg.CollectionID != "pbc_apikeys_plugin" {
		t.Errorf("expected CollectionID 'pbc_apikeys_plugin', got %q", cfg.CollectionID)
	}
	if cfg.HeaderName != "X-API-Key" {
		t.Errorf("expected HeaderName 'X-API-Key', got %q", cfg.HeaderName)
	}
	if cfg.KeyPrefix != "pbk_" {
		t.Errorf("expected KeyPrefix 'pbk_', got %q", cfg.KeyPrefix)
	}
	if cfg.KeyLength != 43 {
		t.Errorf("expected KeyLength 43, got %d", cfg.KeyLength)
	}
	if cfg.MaxKeysPerUser != 0 {
		t.Errorf("expected MaxKeysPerUser 0, got %d", cfg.MaxKeysPerUser)
	}
}

func TestConfigOptions(t *testing.T) {
	cfg := DefaultConfig()
	WithCollectionName("my_keys")(&cfg)
	WithCollectionID("abc123")(&cfg)
	WithHeaderName("X-Custom-Key")(&cfg)
	WithKeyPrefix("myapp_")(&cfg)
	WithKeyLength(20)(&cfg)
	WithMaxKeysPerUser(5)(&cfg)

	if cfg.CollectionName != "my_keys" {
		t.Errorf("WithCollectionName failed: got %q", cfg.CollectionName)
	}
	if cfg.CollectionID != "abc123" {
		t.Errorf("WithCollectionID failed: got %q", cfg.CollectionID)
	}
	if cfg.HeaderName != "X-Custom-Key" {
		t.Errorf("WithHeaderName failed: got %q", cfg.HeaderName)
	}
	if cfg.KeyPrefix != "myapp_" {
		t.Errorf("WithKeyPrefix failed: got %q", cfg.KeyPrefix)
	}
	if cfg.KeyLength != 20 {
		t.Errorf("WithKeyLength failed: got %d", cfg.KeyLength)
	}
	if cfg.MaxKeysPerUser != 5 {
		t.Errorf("WithMaxKeysPerUser failed: got %d", cfg.MaxKeysPerUser)
	}
}

// =============================================================================
// Integration Tests — With TestApp
// =============================================================================

// Helper: bootstrap the plugin collection in a test app.
func bootstrapPlugin(app *tests.TestApp, t testing.TB, cfg Config) {
	if err := ensureCollection(app, cfg); err != nil {
		t.Fatalf("failed to bootstrap plugin collection: %v", err)
	}
}

// Helper: create a test API key record and return the raw key + record ID.
func createTestKeyRecord(app *tests.TestApp, t testing.TB, cfg Config, userId string, disabled bool, expiresAt string) (rawKey string, recordId string) {
	rawKey, keyHash := generateAPIKey(cfg.KeyPrefix, cfg.KeyLength)

	collection, err := app.FindCollectionByNameOrId(cfg.CollectionName)
	if err != nil {
		t.Fatalf("failed to find collection: %v", err)
	}

	record := core.NewRecord(collection)
	record.Set("name", "test-key-"+security.RandomString(6))
	record.Set("key_hash", keyHash)
	record.Set("key_prefix", cfg.KeyPrefix)
	record.Set("user", userId)
	record.Set("disabled", disabled)
	if expiresAt != "" {
		dt, err := types.ParseDateTime(expiresAt)
		if err != nil {
			t.Fatalf("failed to parse expires_at: %v", err)
		}
		record.Set("expires_at", dt)
	}

	if err := app.Save(record); err != nil {
		t.Fatalf("failed to save test key record: %v", err)
	}

	return rawKey, record.Id
}

func TestEnsureCollection_Create(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	cfg := DefaultConfig()
	if err := ensureCollection(app, cfg); err != nil {
		t.Fatalf("ensureCollection failed: %v", err)
	}

	// Verify collection exists
	col, err := app.FindCollectionByNameOrId(cfg.CollectionName)
	if err != nil {
		t.Fatalf("collection %q should exist: %v", cfg.CollectionName, err)
	}

	if col.Name != cfg.CollectionName {
		t.Errorf("expected collection name %q, got %q", cfg.CollectionName, col.Name)
	}

	// Verify fields
	if col.Fields.GetByName("key_hash") == nil {
		t.Error("expected key_hash field")
	}
	if col.Fields.GetByName("key_prefix") == nil {
		t.Error("expected key_prefix field")
	}
	if col.Fields.GetByName("user") == nil {
		t.Error("expected user field")
	}
	if col.Fields.GetByName("disabled") == nil {
		t.Error("expected disabled field")
	}
}

func TestEnsureCollection_NoopOnSecondCall(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	cfg := DefaultConfig()

	// First call — creates
	if err := ensureCollection(app, cfg); err != nil {
		t.Fatalf("first ensureCollection failed: %v", err)
	}

	// Second call — should be no-op
	if err := ensureCollection(app, cfg); err != nil {
		t.Fatalf("second ensureCollection failed: %v", err)
	}

	// Verify still exists
	_, err = app.FindCollectionByNameOrId(cfg.CollectionName)
	if err != nil {
		t.Fatalf("collection should still exist: %v", err)
	}
}

// TestEnsureCollection_MigratesLegacySchema ensures an existing collection
// created by an earlier plugin version is upgraded in place: the autodate
// fields are added and the (previously disabled) create/update rules are
// applied, without touching the stored records.
func TestEnsureCollection_MigratesLegacySchema(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	cfg := DefaultConfig()

	// Simulate the previous release: no created/updated fields, and the generic
	// create/update endpoints turned off.
	legacy := core.NewCollection(core.CollectionTypeBase, cfg.CollectionName, cfg.CollectionID)
	legacy.Fields.Add(&core.TextField{Name: "name", Required: true, Max: 100})
	legacy.Fields.Add(&core.TextField{Name: "key_hash", Required: true, Max: 64, Hidden: true})
	legacy.Fields.Add(&core.TextField{Name: "key_prefix", Required: true, Max: 8})
	legacy.Fields.Add(&core.RelationField{Name: "user", CollectionId: "_pb_users_auth_", MaxSelect: 1, Required: true})
	legacy.Fields.Add(&core.BoolField{Name: "disabled"})
	legacy.Fields.Add(&core.DateField{Name: "expires_at"})
	legacy.ListRule = types.Pointer("user = @request.auth.id")
	legacy.ViewRule = types.Pointer("user = @request.auth.id")
	legacy.DeleteRule = types.Pointer("user = @request.auth.id")
	legacy.CreateRule = nil
	legacy.UpdateRule = nil

	if err := app.Save(legacy); err != nil {
		t.Fatalf("failed to save legacy collection: %v", err)
	}

	// an existing key record must survive the migration
	createTestKeyRecord(app, t, cfg, testUserId, false, "")

	if err := ensureCollection(app, cfg); err != nil {
		t.Fatalf("ensureCollection failed: %v", err)
	}

	col, err := app.FindCollectionByNameOrId(cfg.CollectionName)
	if err != nil {
		t.Fatal(err)
	}

	if col.Fields.GetByName("created") == nil || col.Fields.GetByName("updated") == nil {
		t.Error("expected the autodate fields to be added on migration")
	}
	if col.CreateRule == nil || *col.CreateRule != "@request.auth.id != '' && user = @request.auth.id" {
		t.Errorf("expected the create rule to be enabled on migration, got %v", col.CreateRule)
	}
	if col.UpdateRule == nil || *col.UpdateRule != "user = @request.auth.id" {
		t.Errorf("expected the update rule to be enabled on migration, got %v", col.UpdateRule)
	}

	// reading the records back proves the new columns were really added
	records, err := app.FindAllRecords(cfg.CollectionName)
	if err != nil {
		t.Fatalf("failed to read records after migration: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected the existing record to survive the migration, got %d", len(records))
	}
	if records[0].GetString("key_hash") == "" {
		t.Error("expected the migrated record to keep its key_hash")
	}
}

// =============================================================================
// Middleware Tests — Using ApiScenario
// =============================================================================

func TestApiKeyAuthMiddleware_NoHeader(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "no api key header — middleware does nothing",
			Method: http.MethodGet,
			URL:    "/test-no-header",
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				bootstrapPlugin(app, tb, cfg)
				e.Router.BindFunc(apiKeyAuthMiddleware(app, cfg))
				e.Router.GET("/test-no-header", func(e *core.RequestEvent) error {
					if e.Auth != nil {
						return e.String(200, "authed:"+e.Auth.Id)
					}
					return e.String(200, "guest")
				})
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"guest"},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

// TestApiKeyAuthMiddleware_FullFlow tests the complete middleware authentication flow:
// create a key record, then use it via header to authenticate.
func TestApiKeyAuthMiddleware_FullFlow(t *testing.T) {
	t.Parallel()

	var scenario tests.ApiScenario
	scenario = tests.ApiScenario{
		Name:   "valid api key authenticates",
		Method: http.MethodGet,
		URL:    "/test-full-flow",
		BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			cfg := DefaultConfig()
			bootstrapPlugin(app, tb, cfg)

			// Create a test API key record in this app's DB
			rawKey, _ := createTestKeyRecord(app, tb, cfg, testUserId, false, "")

			e.Router.BindFunc(apiKeyAuthMiddleware(app, cfg))
			e.Router.GET("/test-full-flow", func(e *core.RequestEvent) error {
				if e.Auth != nil {
					return e.JSON(200, map[string]string{"userId": e.Auth.Id})
				}
				return e.JSON(200, map[string]string{"userId": ""})
			})

			// Mutate Headers via closure — BeforeTestFunc runs BEFORE headers are read
			scenario.Headers = map[string]string{
				cfg.HeaderName: rawKey,
			}
		},
		ExpectedStatus:  200,
		ExpectedContent: []string{`"userId":"` + testUserId + `"`},
	}

	scenario.Test(t)
}

func TestApiKeyAuthMiddleware_InvalidPrefix(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "key with wrong prefix — does not authenticate",
			Method: http.MethodGet,
			URL:    "/test-bad-prefix",
			Headers: map[string]string{
				"X-API-Key": "bad_keythatisverylongandshouldnotwork",
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				bootstrapPlugin(app, tb, cfg)
				e.Router.BindFunc(apiKeyAuthMiddleware(app, cfg))
				e.Router.GET("/test-bad-prefix", func(e *core.RequestEvent) error {
					if e.Auth != nil {
						return e.String(200, "authed")
					}
					return e.String(200, "guest")
				})
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"guest"},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestApiKeyAuthMiddleware_NonexistentKey(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "valid prefix but nonexistent key — does not authenticate",
			Method: http.MethodGet,
			URL:    "/test-fake-key",
			Headers: map[string]string{
				"X-API-Key": "pbk_nonexistentkeythatdoesnotexist",
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				bootstrapPlugin(app, tb, cfg)
				e.Router.BindFunc(apiKeyAuthMiddleware(app, cfg))
				e.Router.GET("/test-fake-key", func(e *core.RequestEvent) error {
					if e.Auth != nil {
						return e.String(200, "authed")
					}
					return e.String(200, "guest")
				})
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"guest"},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestApiKeyAuthMiddleware_DisabledKey(t *testing.T) {
	t.Parallel()

	var scenario tests.ApiScenario
	scenario = tests.ApiScenario{
		Name:   "disabled key — does not authenticate",
		Method: http.MethodGet,
		URL:    "/test-disabled-key",
		BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			cfg := DefaultConfig()
			bootstrapPlugin(app, tb, cfg)

			// Create a disabled key in this app's DB
			rawKey, _ := createTestKeyRecord(app, tb, cfg, testUserId, true, "")

			e.Router.BindFunc(apiKeyAuthMiddleware(app, cfg))
			e.Router.GET("/test-disabled-key", func(e *core.RequestEvent) error {
				if e.Auth != nil {
					return e.String(200, "authed")
				}
				return e.String(200, "guest")
			})

			// Mutate Headers via closure
			scenario.Headers = map[string]string{
				cfg.HeaderName: rawKey,
			}
		},
		ExpectedStatus:  200,
		ExpectedContent: []string{"guest"},
	}

	scenario.Test(t)
}

func TestApiKeyAuthMiddleware_AlreadyAuthed(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "already authenticated by JWT — middleware skips",
			Method: http.MethodGet,
			URL:    "/test-already-authed",
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				bootstrapPlugin(app, tb, cfg)
				e.Router.BindFunc(apiKeyAuthMiddleware(app, cfg))
				e.Router.GET("/test-already-authed", func(e *core.RequestEvent) error {
					if e.Auth != nil {
						return e.String(200, "authed:"+e.Auth.Id)
					}
					return e.String(200, "guest")
				})
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{"authed:" + testUserId},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

// =============================================================================
// Create Tests — built-in Record API (POST /api/collections/apiKeys/records)
// =============================================================================

// recordsURL is the built-in Record API endpoint for the apiKeys collection.
const recordsURL = "/api/collections/apiKeys/records"

// bootstrapHooks bootstraps the collection and registers the request hooks.
func bootstrapHooks(app *tests.TestApp, t testing.TB, cfg Config) {
	bootstrapPlugin(app, t, cfg)
	registerRequestHooks(app, cfg)
}

// createTestKeyNamed inserts a key record with an explicit name, used to set up
// unique-index conflicts.
func createTestKeyNamed(app *tests.TestApp, t testing.TB, cfg Config, userId string, name string) {
	collection, err := app.FindCollectionByNameOrId(cfg.CollectionName)
	if err != nil {
		t.Fatalf("failed to find collection: %v", err)
	}

	record := core.NewRecord(collection)
	record.Set("name", name)
	record.Set("key_hash", security.SHA256(cfg.KeyPrefix+security.RandomString(40)))
	record.Set("key_prefix", cfg.KeyPrefix)
	record.Set("user", userId)

	if err := app.Save(record); err != nil {
		t.Fatalf("failed to save test key record: %v", err)
	}
}

// createSecondUser creates an additional user in the test app and returns its id.
// Relation fields are validated, so ownership tests need a real user record.
func createSecondUser(tb testing.TB, app *tests.TestApp) string {
	collection, err := app.FindCollectionByNameOrId("users")
	if err != nil {
		tb.Fatal(err)
	}

	record := core.NewRecord(collection)
	record.Set("email", "other@example.com")
	record.Set("password", "password123456")
	record.Set("verified", true)
	if err := app.Save(record); err != nil {
		tb.Fatal(err)
	}

	return record.Id
}

// superuserToken creates a superuser in the test app and returns its auth token.
func superuserToken(tb testing.TB, app *tests.TestApp) string {
	collection, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		tb.Fatal(err)
	}

	record := core.NewRecord(collection)
	record.Set("email", "root@example.com")
	record.Set("password", security.RandomString(20))
	if err := app.Save(record); err != nil {
		tb.Fatal(err)
	}

	token, err := record.NewAuthToken()
	if err != nil {
		tb.Fatal(err)
	}

	return token
}

func TestCreateKey_Success(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	scenarios := []tests.ApiScenario{
		{
			Name:   "owner can create a key and receives it once",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body: strings.NewReader(
				`{"name":"CI Server","user":"` + testUserId + `","expires_at":"2027-01-01 00:00:00.000Z"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"name":"CI Server"`,
				`"key":"` + cfg.KeyPrefix,
				`"key_prefix":"` + cfg.KeyPrefix + `"`,
				`"disabled":false`,
				`"user":"` + testUserId + `"`,
				`"expires_at":"2027-01-01 00:00:00.000Z"`,
				// created/updated come from the autodate fields
				`"created":"`,
				`"updated":"`,
			},
			NotExpectedContent: []string{`"key_hash"`},
			AfterTestFunc: func(tb testing.TB, app *tests.TestApp, res *http.Response) {
				body, err := io.ReadAll(res.Body)
				if err != nil {
					tb.Fatal(err)
				}

				var created struct {
					Key string `json:"key"`
				}
				if err := json.Unmarshal(body, &created); err != nil {
					tb.Fatal(err)
				}

				records, err := app.FindAllRecords(cfg.CollectionName)
				if err != nil {
					tb.Fatal(err)
				}
				if len(records) != 1 {
					tb.Fatalf("expected exactly 1 record, got %d", len(records))
				}

				// The stored hash must match the returned key, and the plaintext
				// value must not be reachable anywhere in the stored data.
				storedHash := records[0].GetString("key_hash")
				if storedHash != security.SHA256(created.Key) {
					tb.Error("stored key_hash does not match the returned key")
				}

				// nothing that reaches SQL may contain the plaintext key
				exported, err := records[0].DBExport(app)
				if err != nil {
					tb.Fatal(err)
				}
				for column, value := range exported {
					if strings.Contains(fmt.Sprint(value), created.Key) {
						tb.Errorf("the plaintext key leaked into column %q", column)
					}
				}
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestCreateKey_ServerOwnedFieldsAreForced(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	scenarios := []tests.ApiScenario{
		{
			Name:   "client supplied key_hash/key_prefix/disabled are overwritten",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body: strings.NewReader(`{"name":"forced","user":"` + testUserId + `",` +
				`"key_hash":"deadbeefdeadbeefdeadbeefdeadbeef","key_prefix":"xxx_","disabled":true}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
			},
			ExpectedStatus: 200,
			ExpectedContent: []string{
				`"key":"` + cfg.KeyPrefix,
				`"key_prefix":"` + cfg.KeyPrefix + `"`,
				`"disabled":false`,
			},
			NotExpectedContent: []string{
				`"key_hash"`,
				`"xxx_"`,
				`deadbeef`,
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestCreateKey_Validation(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	scenarios := []tests.ApiScenario{
		{
			Name:   "missing name fails field validation",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body:   strings.NewReader(`{"user":"` + testUserId + `"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
			},
			ExpectedStatus: 400,
			ExpectedContent: []string{
				`"validation_required"`,
			},
			NotExpectedContent: []string{`"key"`},
		},
		{
			Name:   "claiming another user as owner is rejected by the create rule",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body:   strings.NewReader(`{"name":"sneaky","user":"someoneelse"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
			},
			ExpectedStatus:     400,
			NotExpectedContent: []string{`"key"`},
		},
		{
			Name:   "omitting the owner is rejected by the create rule",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body:   strings.NewReader(`{"name":"ownerless"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
			},
			ExpectedStatus:     400,
			NotExpectedContent: []string{`"key"`},
		},
		{
			Name:   "guest cannot create a key",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body:   strings.NewReader(`{"name":"guest","user":"` + testUserId + `"}`),
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
			},
			ExpectedStatus:     400,
			NotExpectedContent: []string{`"key"`},
		},
		{
			Name:   "invalid expires_at is rejected",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body:   strings.NewReader(`{"name":"bad date","user":"` + testUserId + `","expires_at":"not-a-date"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
			},
			ExpectedStatus:     400,
			NotExpectedContent: []string{`"key"`},
		},
		{
			Name:   "duplicate name per user is rejected by the unique index",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body:   strings.NewReader(`{"name":"duplicate","user":"` + testUserId + `"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				createTestKeyNamed(app, tb, cfg, testUserId, "duplicate")
			},
			ExpectedStatus:     400,
			NotExpectedContent: []string{`"key"`},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestCreateKey_ExpiryFormats(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	scenarios := []tests.ApiScenario{
		{
			Name:   "ISO 8601 expiry is accepted and normalized",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body:   strings.NewReader(`{"name":"iso","user":"` + testUserId + `","expires_at":"2028-01-01T00:00:00Z"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"expires_at":"2028-01-01 00:00:00.000Z"`},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestCreateKey_MaxKeysPerUser(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()
	cfg.MaxKeysPerUser = 1

	scenarios := []tests.ApiScenario{
		{
			Name:   "creating a key over the limit is rejected",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body:   strings.NewReader(`{"name":"one too many","user":"` + testUserId + `"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				createTestKeyRecord(app, tb, cfg, testUserId, false, "")
			},
			ExpectedStatus:     400,
			ExpectedContent:    []string{"Maximum of 1 active API keys reached"},
			NotExpectedContent: []string{`"key"`},
		},
		{
			Name:   "a disabled key does not count towards the limit",
			Method: http.MethodPost,
			URL:    recordsURL,
			Body:   strings.NewReader(`{"name":"after revoke","user":"` + testUserId + `"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				createTestKeyRecord(app, tb, cfg, testUserId, true, "")
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"key":"` + cfg.KeyPrefix},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestCreateKey_SuperuserMayAssignOwner(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	var scenario tests.ApiScenario
	scenario = tests.ApiScenario{
		Name:   "superuser can create a key for another user",
		Method: http.MethodPost,
		URL:    recordsURL,
		Body:   strings.NewReader(`{"name":"on behalf","user":"` + testUserId + `"}`),
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			bootstrapHooks(app, tb, cfg)
			scenario.Headers["Authorization"] = superuserToken(tb, app)
		},
		ExpectedStatus:  200,
		ExpectedContent: []string{`"key":"` + cfg.KeyPrefix, `"user":"` + testUserId + `"`},
	}

	scenario.Test(t)
}

// =============================================================================
// Config Tests
// =============================================================================

func TestWithHeaderName(t *testing.T) {
	cfg := DefaultConfig()
	WithHeaderName("X-Custom-Header")(&cfg)
	if cfg.HeaderName != "X-Custom-Header" {
		t.Errorf("expected 'X-Custom-Header', got %q", cfg.HeaderName)
	}
}

func TestWithKeyPrefix_Invalid_Extended(t *testing.T) {
	// Additional edge cases beyond TestValidateKeyPrefix_Invalid.
	invalidPrefixes := []string{"", "a_", "toolongs_", "noUnderscore", "bad-chars_"}
	for _, p := range invalidPrefixes {
		if err := validateKeyPrefix(p); err == nil {
			t.Errorf("expected error for invalid prefix %q", p)
		}
	}
}

// =============================================================================
// Config Validation Tests
// =============================================================================

func TestValidateConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		keyLength  int
		keyPrefix  string
		wantErr    bool
		errContain string
	}{
		{name: "valid", keyLength: 43, keyPrefix: "pbk_", wantErr: false},
		{name: "exactly minimum", keyLength: 32, keyPrefix: "app_", wantErr: false},
		{name: "zero length", keyLength: 0, keyPrefix: "pbk_", wantErr: true, errContain: "key length"},
		{name: "negative length", keyLength: -5, keyPrefix: "pbk_", wantErr: true, errContain: "key length"},
		{name: "one below minimum", keyLength: 31, keyPrefix: "pbk_", wantErr: true, errContain: "key length"},
		{name: "invalid prefix", keyLength: 43, keyPrefix: "no", wantErr: true, errContain: "key prefix"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				KeyPrefix: tt.keyPrefix,
				KeyLength: tt.keyLength,
			}
			err := validateConfig(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateConfig() error = %v, wantErr = %v", err, tt.wantErr)
			}
			if err != nil && tt.errContain != "" {
				if !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("expected error to contain %q, got %q", tt.errContain, err.Error())
				}
			}
		})
	}
}

// =============================================================================
// Update Tests — built-in Record API (PATCH /api/collections/apiKeys/records/:id)
// =============================================================================

func TestUpdateKey_Rename(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	var scenarios []tests.ApiScenario
	scenarios = []tests.ApiScenario{
		{
			Name:   "rename a key",
			Method: http.MethodPatch,
			URL:    "", // set in BeforeTestFunc
			Body:   strings.NewReader(`{"name":"Renamed Key"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				_, recordId := createTestKeyRecord(app, tb, cfg, testUserId, false, "")
				scenarios[0].URL = recordsURL + "/" + recordId
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"name":"Renamed Key"`},
		},
	}

	for i := range scenarios {
		scenarios[i].Test(t)
	}
}

func TestUpdateKey_Disable(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	var scenarios []tests.ApiScenario
	scenarios = []tests.ApiScenario{
		{
			Name:   "disable a key",
			Method: http.MethodPatch,
			URL:    "",
			Body:   strings.NewReader(`{"disabled":true}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				_, recordId := createTestKeyRecord(app, tb, cfg, testUserId, false, "")
				scenarios[0].URL = recordsURL + "/" + recordId
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"disabled":true`},
		},
	}

	for i := range scenarios {
		scenarios[i].Test(t)
	}
}

func TestUpdateKey_SetAndClearExpiry(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	var scenarios []tests.ApiScenario
	scenarios = []tests.ApiScenario{
		{
			Name:   "set expiry",
			Method: http.MethodPatch,
			URL:    "",
			Body:   strings.NewReader(`{"expires_at":"2028-06-01 00:00:00.000Z"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				_, recordId := createTestKeyRecord(app, tb, cfg, testUserId, false, "")
				scenarios[0].URL = recordsURL + "/" + recordId
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"expires_at":"2028-06-01 00:00:00.000Z"`},
		},
		{
			Name:   "clear expiry",
			Method: http.MethodPatch,
			URL:    "",
			Body:   strings.NewReader(`{"expires_at":""}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				_, recordId := createTestKeyRecord(app, tb, cfg, testUserId, false, "2028-06-01 00:00:00.000Z")
				scenarios[1].URL = recordsURL + "/" + recordId
			},
			ExpectedStatus:     200,
			ExpectedContent:    []string{`"expires_at":""`},
			NotExpectedContent: []string{`"expires_at":"2028-06-01`},
		},
	}

	for i := range scenarios {
		scenarios[i].Test(t)
	}
}

func TestUpdateKey_ImmutableFields(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	for _, field := range []string{"user", "key_prefix", "id", "created", "updated", "key"} {
		field := field
		t.Run(field, func(t *testing.T) {
			t.Parallel()

			var scenarios []tests.ApiScenario
			scenarios = []tests.ApiScenario{
				{
					Name:   "changing " + field + " is rejected",
					Method: http.MethodPatch,
					URL:    "",
					Body:   strings.NewReader(`{"` + field + `":"tampered"}`),
					Headers: map[string]string{
						"Authorization": testUserToken,
					},
					BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
						bootstrapHooks(app, tb, cfg)
						_, recordId := createTestKeyRecord(app, tb, cfg, testUserId, false, "")
						scenarios[0].URL = recordsURL + "/" + recordId
					},
					ExpectedStatus: 400,
					ExpectedContent: []string{
						fmt.Sprintf("\\\"%s\\\" is immutable", field),
					},
				},
			}

			for i := range scenarios {
				scenarios[i].Test(t)
			}
		})
	}
}

func TestUpdateKey_HashCannotBeSpoofed(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	var hashBefore, hashAfter string

	var scenarios []tests.ApiScenario
	scenarios = []tests.ApiScenario{
		{
			Name:   "the hidden key_hash field cannot be overwritten",
			Method: http.MethodPatch,
			URL:    "",
			Body:   strings.NewReader(`{"key_hash":"deadbeefdeadbeefdeadbeefdeadbeef","name":"still mine"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				_, recordId := createTestKeyRecord(app, tb, cfg, testUserId, false, "")
				scenarios[0].URL = recordsURL + "/" + recordId

				record, err := app.FindRecordById(cfg.CollectionName, recordId)
				if err != nil {
					tb.Fatal(err)
				}
				hashBefore = record.GetString("key_hash")
			},
			// the raw body is checked, so an explicit attempt to set the hidden
			// key_hash field is rejected outright instead of being ignored
			ExpectedStatus:     400,
			ExpectedContent:    []string{`is immutable`},
			NotExpectedContent: []string{"deadbeef"},
			AfterTestFunc: func(tb testing.TB, app *tests.TestApp, res *http.Response) {
				records, err := app.FindAllRecords(cfg.CollectionName)
				if err != nil {
					tb.Fatal(err)
				}
				hashAfter = records[0].GetString("key_hash")
			},
		},
	}

	for i := range scenarios {
		scenarios[i].Test(t)
	}

	if hashBefore == "" {
		t.Fatal("expected the stored hash to be captured before the request")
	}
	if hashBefore != hashAfter {
		t.Errorf("key_hash changed from %q to %q", hashBefore, hashAfter)
	}
}

func TestUpdateKey_EmptyName(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	var scenarios []tests.ApiScenario
	scenarios = []tests.ApiScenario{
		{
			Name:   "clearing the name fails validation",
			Method: http.MethodPatch,
			URL:    "",
			Body:   strings.NewReader(`{"name":""}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				_, recordId := createTestKeyRecord(app, tb, cfg, testUserId, false, "")
				scenarios[0].URL = recordsURL + "/" + recordId
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"validation_required"`},
		},
	}

	for i := range scenarios {
		scenarios[i].Test(t)
	}
}

func TestUpdateKey_AccessControl(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	var scenarios []tests.ApiScenario
	scenarios = []tests.ApiScenario{
		{
			Name:   "another user cannot update the key",
			Method: http.MethodPatch,
			URL:    "",
			Body:   strings.NewReader(`{"name":"hijacked"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				// owned by a different, real user
				_, recordId := createTestKeyRecord(app, tb, cfg, createSecondUser(tb, app), false, "")
				scenarios[0].URL = recordsURL + "/" + recordId
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"status":404`},
		},
		{
			Name:   "guest cannot update a key",
			Method: http.MethodPatch,
			URL:    "",
			Body:   strings.NewReader(`{"name":"hijacked"}`),
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				_, recordId := createTestKeyRecord(app, tb, cfg, testUserId, false, "")
				scenarios[1].URL = recordsURL + "/" + recordId
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"status":404`},
		},
		{
			Name:   "unknown key id returns 404",
			Method: http.MethodPatch,
			URL:    recordsURL + "/nonexistentid123",
			Body:   strings.NewReader(`{"name":"ghost"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"status":404`},
		},
	}

	for i := range scenarios {
		scenarios[i].Test(t)
	}
}

// =============================================================================
// Delete Tests — built-in Record API (DELETE /api/collections/apiKeys/records/:id)
// =============================================================================

func TestDeleteKey_Owner(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	var scenarios []tests.ApiScenario
	scenarios = []tests.ApiScenario{
		{
			Name:   "owner can delete their key",
			Method: http.MethodDelete,
			URL:    "",
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				_, recordId := createTestKeyRecord(app, tb, cfg, testUserId, false, "")
				scenarios[0].URL = recordsURL + "/" + recordId
			},
			// no content expectations => the harness asserts an empty body
			ExpectedStatus: 204,
			AfterTestFunc: func(tb testing.TB, app *tests.TestApp, res *http.Response) {
				records, err := app.FindAllRecords(cfg.CollectionName)
				if err != nil {
					tb.Fatal(err)
				}
				if len(records) != 0 {
					tb.Errorf("expected the record to be gone, got %d records", len(records))
				}
			},
		},
	}

	for i := range scenarios {
		scenarios[i].Test(t)
	}
}

func TestDeleteKey_AccessControl(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	var scenarios []tests.ApiScenario
	scenarios = []tests.ApiScenario{
		{
			Name:   "another user cannot delete the key",
			Method: http.MethodDelete,
			URL:    "",
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				_, recordId := createTestKeyRecord(app, tb, cfg, createSecondUser(tb, app), false, "")
				scenarios[0].URL = recordsURL + "/" + recordId
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"status":404`},
		},
		{
			Name:   "guest cannot delete a key",
			Method: http.MethodDelete,
			URL:    "",
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)
				_, recordId := createTestKeyRecord(app, tb, cfg, testUserId, false, "")
				scenarios[1].URL = recordsURL + "/" + recordId
			},
			ExpectedStatus:  404,
			ExpectedContent: []string{`"status":404`},
		},
	}

	for i := range scenarios {
		scenarios[i].Test(t)
	}
}

// =============================================================================
// Batch API — POST /api/batch
// =============================================================================

func TestBatchRequest_GoesThroughHooks(t *testing.T) {
	t.Parallel()

	cfg := DefaultConfig()

	var scenarios []tests.ApiScenario
	scenarios = []tests.ApiScenario{
		{
			Name:   "a batched create still generates the key",
			Method: http.MethodPost,
			URL:    "/api/batch",
			Body: strings.NewReader(`{"requests":[{"method":"POST",` +
				`"url":"/api/collections/apiKeys/records",` +
				`"body":{"name":"batched","user":"` + testUserId + `"}}]}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				bootstrapHooks(app, tb, cfg)

				// The batch API is disabled by default.
				settings := app.Settings()
				settings.Batch.Enabled = true
				if err := app.Save(settings); err != nil {
					tb.Fatal(err)
				}
			},
			ExpectedStatus:  200,
			ExpectedContent: []string{`"key":"` + cfg.KeyPrefix, `"status":200`},
			NotExpectedContent: []string{
				`"key_hash"`,
			},
		},
	}

	for i := range scenarios {
		scenarios[i].Test(t)
	}
}

// =============================================================================
// End-to-end — a key returned by create authenticates the next request
// =============================================================================

func TestEndToEnd_CreateThenAuthenticate(t *testing.T) {
	t.Parallel()

	app, err := tests.NewTestApp()
	if err != nil {
		t.Fatal(err)
	}
	defer app.Cleanup()

	cfg := DefaultConfig()
	bootstrapHooks(app, t, cfg)

	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}

	serveEvent := new(core.ServeEvent)
	serveEvent.App = app
	serveEvent.Router = router

	err = app.OnServe().Trigger(serveEvent, func(e *core.ServeEvent) error {
		e.Router.BindFunc(apiKeyAuthMiddleware(app, cfg))
		e.Router.GET("/test-whoami", func(re *core.RequestEvent) error {
			if re.Auth == nil {
				return re.JSON(http.StatusOK, map[string]string{"userId": ""})
			}
			return re.JSON(http.StatusOK, map[string]string{"userId": re.Auth.Id})
		})
		return e.Next()
	})
	if err != nil {
		t.Fatal(err)
	}

	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}

	// 1. create a key through the built-in API
	createReq := httptest.NewRequest(
		http.MethodPost,
		recordsURL,
		strings.NewReader(`{"name":"e2e","user":"`+testUserId+`"}`),
	)
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set("Authorization", testUserToken)

	createRec := httptest.NewRecorder()
	mux.ServeHTTP(createRec, createReq)

	if createRec.Code != http.StatusOK {
		t.Fatalf("expected create status 200, got %d: %s", createRec.Code, createRec.Body.String())
	}

	created := struct {
		Key string `json:"key"`
	}{}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Key, cfg.KeyPrefix) {
		t.Fatalf("expected a %q prefixed key, got %q", cfg.KeyPrefix, created.Key)
	}

	// 2. use the returned key as the authentication header
	whoamiReq := httptest.NewRequest(http.MethodGet, "/test-whoami", nil)
	whoamiReq.Header.Set(cfg.HeaderName, created.Key)

	whoamiRec := httptest.NewRecorder()
	mux.ServeHTTP(whoamiRec, whoamiReq)

	if whoamiRec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", whoamiRec.Code)
	}
	if !strings.Contains(whoamiRec.Body.String(), `"userId":"`+testUserId+`"`) {
		t.Errorf("expected the created key to authenticate as %q, got %s", testUserId, whoamiRec.Body.String())
	}

	// 3. a disabled key must stop authenticating
	records, err := app.FindAllRecords(cfg.CollectionName)
	if err != nil {
		t.Fatal(err)
	}
	records[0].Set("disabled", true)
	if err := app.Save(records[0]); err != nil {
		t.Fatal(err)
	}

	revokedRec := httptest.NewRecorder()
	mux.ServeHTTP(revokedRec, whoamiReq)

	if !strings.Contains(revokedRec.Body.String(), `"userId":""`) {
		t.Errorf("expected a disabled key to stop authenticating, got %s", revokedRec.Body.String())
	}
}
