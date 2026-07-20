package apikeyauth

import (
	"net/http"
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

	expectedFields := []string{"name", "key_hash", "key_prefix", "user", "disabled", "expires_at"}
	// Field count: 6 custom fields + 1 auto system field (id) = 7
	if len(c.Fields) != 7 {
		t.Errorf("expected 7 fields (6 custom + id), got %d", len(c.Fields))
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

	// API Rules
	if c.ListRule == nil || *c.ListRule != "user = @request.auth.id" {
		t.Error("ListRule not set correctly")
	}
	if c.ViewRule == nil || *c.ViewRule != "user = @request.auth.id" {
		t.Error("ViewRule not set correctly")
	}
	if c.CreateRule == nil || *c.CreateRule != "user = @request.auth.id" {
		t.Error("CreateRule not set correctly")
	}
	if c.UpdateRule == nil || *c.UpdateRule != "user = @request.auth.id" {
		t.Error("UpdateRule not set correctly")
	}
	if c.DeleteRule == nil || *c.DeleteRule != "user = @request.auth.id" {
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

	if cfg.CollectionName != "api_keys" {
		t.Errorf("expected CollectionName 'api_keys', got %q", cfg.CollectionName)
	}
	if cfg.CollectionID != "pbc_apikeys_plugin" {
		t.Errorf("expected CollectionID 'pbc_apikeys_plugin', got %q", cfg.CollectionID)
	}
	if cfg.HeaderName != "X-API-Key" {
		t.Errorf("expected HeaderName 'X-API-Key', got %q", cfg.HeaderName)
	}
	if cfg.ApiPath != "/api/api-key" {
		t.Errorf("expected ApiPath '/api/api-key', got %q", cfg.ApiPath)
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
	WithApiPath("/api/custom")(&cfg)
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
	if cfg.ApiPath != "/api/custom" {
		t.Errorf("WithApiPath failed: got %q", cfg.ApiPath)
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
// Handler Tests — Create API Key
// =============================================================================

func TestCreateAPIKeyHandler_Success(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "create api key with valid name",
			Method: http.MethodPost,
			URL:    "/api/api-key",
			Body:   strings.NewReader(`{"name":"My Test Key"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
				"Content-Type":  "application/json",
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				bootstrapPlugin(app, tb, cfg)
				e.Router.POST(cfg.ApiPath, createAPIKeyHandler(app, cfg)).
					Bind(apis.RequireAuth())
			},
			ExpectedStatus: 201,
			ExpectedContent: []string{
				`"name":"My Test Key"`,
				`"key":"pbk_`,
				`"key_prefix":"pbk_"`,
				`"user":"` + testUserId + `"`,
				`"disabled":false`,
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestCreateAPIKeyHandler_NoName(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "create api key without name — bad request",
			Method: http.MethodPost,
			URL:    "/api/api-key",
			Body:   strings.NewReader(`{}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
				"Content-Type":  "application/json",
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				bootstrapPlugin(app, tb, cfg)
				e.Router.POST(cfg.ApiPath, createAPIKeyHandler(app, cfg)).
					Bind(apis.RequireAuth())
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"status":400`},
		},
		{
			Name:   "create api key with whitespace name — bad request",
			Method: http.MethodPost,
			URL:    "/api/api-key",
			Body:   strings.NewReader(`{"name":"   "}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
				"Content-Type":  "application/json",
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				bootstrapPlugin(app, tb, cfg)
				e.Router.POST(cfg.ApiPath, createAPIKeyHandler(app, cfg)).
					Bind(apis.RequireAuth())
			},
			ExpectedStatus:  400,
			ExpectedContent: []string{`"status":400`},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestCreateAPIKeyHandler_Unauthenticated(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "create api key without auth — unauthorized",
			Method: http.MethodPost,
			URL:    "/api/api-key",
			Body:   strings.NewReader(`{"name":"Test"}`),
			Headers: map[string]string{
				"Content-Type": "application/json",
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				bootstrapPlugin(app, tb, cfg)
				e.Router.POST(cfg.ApiPath, createAPIKeyHandler(app, cfg)).
					Bind(apis.RequireAuth())
			},
			ExpectedStatus:  401,
			ExpectedContent: []string{`"status":401`},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestCreateAPIKeyHandler_MaxKeysPerUser(t *testing.T) {
	t.Parallel()

	scenario := tests.ApiScenario{
		Name:   "exceed max keys per user — bad request",
		Method: http.MethodPost,
		URL:    "/api/api-key",
		Body:   strings.NewReader(`{"name":"Third Key"}`),
		Headers: map[string]string{
			"Authorization": testUserToken,
			"Content-Type":  "application/json",
		},
		BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
			cfg := DefaultConfig()
			cfg.MaxKeysPerUser = 2
			bootstrapPlugin(app, tb, cfg)

			// Create two active keys to fill up the quota
			createTestKeyRecord(app, tb, cfg, testUserId, false, "")
			createTestKeyRecord(app, tb, cfg, testUserId, false, "")

			e.Router.POST(cfg.ApiPath, createAPIKeyHandler(app, cfg)).
				Bind(apis.RequireAuth())
		},
		ExpectedStatus:  400,
		ExpectedContent: []string{`"status":400`},
	}

	scenario.Test(t)
}
func TestCreateAPIKeyHandler_WithExpiry(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "create api key with expiry date",
			Method: http.MethodPost,
			URL:    "/api/api-key",
			Body:   strings.NewReader(`{"name":"Expiring Key","expires_at":"2099-12-31 23:59:59.000Z"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
				"Content-Type":  "application/json",
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				bootstrapPlugin(app, tb, cfg)
				e.Router.POST(cfg.ApiPath, createAPIKeyHandler(app, cfg)).
					Bind(apis.RequireAuth())
			},
			ExpectedStatus: 201,
			ExpectedContent: []string{
				`"name":"Expiring Key"`,
				`"expires_at":"2099-12-31`,
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestCreateAPIKeyHandler_InvalidExpiry(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "create api key with unparseable expiry — treated as no expiry (201)",
			Method: http.MethodPost,
			URL:    "/api/api-key",
			Body:   strings.NewReader(`{"name":"Bad Expiry","expires_at":"not-a-date"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
				"Content-Type":  "application/json",
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				bootstrapPlugin(app, tb, cfg)
				e.Router.POST(cfg.ApiPath, createAPIKeyHandler(app, cfg)).
					Bind(apis.RequireAuth())
			},
			ExpectedStatus: 201,
			ExpectedContent: []string{
				`"name":"Bad Expiry"`,
				`"expires_at":""`,
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
}

func TestCreateAPIKeyHandler_CustomPath(t *testing.T) {
	t.Parallel()

	scenarios := []tests.ApiScenario{
		{
			Name:   "create api key on custom path",
			Method: http.MethodPost,
			URL:    "/api/custom-keys",
			Body:   strings.NewReader(`{"name":"Custom Path Key"}`),
			Headers: map[string]string{
				"Authorization": testUserToken,
				"Content-Type":  "application/json",
			},
			BeforeTestFunc: func(tb testing.TB, app *tests.TestApp, e *core.ServeEvent) {
				cfg := DefaultConfig()
				cfg.ApiPath = "/api/custom-keys"
				bootstrapPlugin(app, tb, cfg)
				e.Router.POST(cfg.ApiPath, createAPIKeyHandler(app, cfg)).
					Bind(apis.RequireAuth())
			},
			ExpectedStatus: 201,
			ExpectedContent: []string{
				`"name":"Custom Path Key"`,
				`"key":"pbk_`,
			},
		},
	}

	for _, s := range scenarios {
		s.Test(t)
	}
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
