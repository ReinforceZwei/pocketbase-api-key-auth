# API Key Authentication Plugin — Implementation Plan

## Resolved Design Decisions

| Question | Decision |
|---|---|
| Key hashing? | **Yes** — SHA-256 hash stored; raw key returned only once at creation |
| Key revocation? | **Yes** — `disabled` boolean field |
| Key expiry? | **Yes** — optional `expires_at` datetime field |
| Scoped permissions? | **No** — full user impersonation |
| Multiple keys per user? | **Yes** — each key has a `name` (user-friendly note) |
| Key prefix? | **Yes** — defaults to `pbk_`, customizable via `Config.KeyPrefix` |

---

## Package Structure

```
apikeyauth/
├── apikeyauth.go       # Config, Register(), functional options, public API
├── collection.go       # desiredCollection(), ensureCollection()
├── middleware.go        # apiKeyAuthMiddleware()
├── handlers.go          # POST /api/api-key (create only; other ops via PocketBase CRUD)
├── keygen.go            # generateAPIKey(), validateKeyPrefix()
├── apikeyauth_test.go   # Tests
└── README.md
```

---

## 1. Configuration & Functional Options

### `Config` struct

All customization is done through a `Config` struct passed to `Register()`. Sensible defaults are provided so zero-config works out of the box. The consumer uses functional options to override defaults.

```go
package apikeyauth

// Config holds all customizable settings for the plugin.
// All fields are optional — defaults are applied via DefaultConfig().
type Config struct {
    // CollectionName is the name of the collection that stores API keys.
    // Default: "api_keys"
    CollectionName string

    // CollectionID is the stable ID for the api_keys collection.
    // Changing this after initial deployment is NOT recommended — existing
    // records won't be found. Default: "pbc_apikeys_plugin"
    CollectionID string

    // HeaderName is the HTTP header to read the API key from.
    // Default: "X-API-Key"
    HeaderName string

    // ApiPath is the route path for the key creation endpoint.
    // Default: "/api/api-key"
    ApiPath string

    // KeyPrefix is prepended to every generated API key.
    // Used for identification, auditing, and secret scanning.
    // Must be 3–8 alphanumeric characters + trailing underscore.
    // Default: "pbk_"
    KeyPrefix string

    // KeyLength is the number of random characters in the key (after the prefix).
    // The raw key will be KeyPrefix + security.RandomString(KeyLength).
    // Result matches [A-Za-z0-9]+ — URL-safe by design.
    // Default: 43 (combined with "pbk_" gives ~47 chars)
    KeyLength int

    // MaxKeysPerUser limits how many active (non-disabled, non-expired) keys
    // a single user can have. 0 = unlimited. Default: 0
    MaxKeysPerUser int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
    return Config{
        CollectionName: "api_keys",
        CollectionID:   "pbc_apikeys_plugin",
        HeaderName:     "X-API-Key",
        ApiPath:        "/api/api-key",
        KeyPrefix:      "pbk_",
        KeyLength:      43,
        MaxKeysPerUser: 0,
    }
}

// Option is a functional option for configuring the plugin.
type Option func(*Config)

// WithCollectionName overrides the collection name.
func WithCollectionName(name string) Option {
    return func(c *Config) { c.CollectionName = name }
}

// WithCollectionID overrides the collection ID.
func WithCollectionID(id string) Option {
    return func(c *Config) { c.CollectionID = id }
}

// WithHeaderName overrides the header used to pass the API key.
func WithHeaderName(name string) Option {
    return func(c *Config) { c.HeaderName = name }
}

// WithApiPath overrides the API route path for key creation.
func WithApiPath(path string) Option {
    return func(c *Config) { c.ApiPath = path }
}

// WithKeyPrefix overrides the key prefix (e.g. "myapp_").
func WithKeyPrefix(prefix string) Option {
    return func(c *Config) { c.KeyPrefix = prefix }
}

// WithKeyLength sets the random character length of the generated key.
func WithKeyLength(length int) Option {
    return func(c *Config) { c.KeyLength = length }
}

// WithMaxKeysPerUser limits how many active keys a user can create.
func WithMaxKeysPerUser(max int) Option {
    return func(c *Config) { c.MaxKeysPerUser = max }
}
```

### Consumer usage (with customization)

```go
package main

import (
    "log"
    "github.com/pocketbase/pocketbase"
    "github.com/ReinforceZwei/pocketbase-api-key-auth/apikeyauth"
)

func main() {
    app := pocketbase.New()

    apikeyauth.Register(app,
        apikeyauth.WithHeaderName("X-MyApp-Key"),
        apikeyauth.WithKeyPrefix("myapp_"),
        apikeyauth.WithApiPath("/api/custom-keys"),
        apikeyauth.WithMaxKeysPerUser(5),
    )

    if err := app.Start(); err != nil {
        log.Fatal(err)
    }
}
```

---

## 2. Key Generation & Hashing

Uses PocketBase's own [`security`](https://pkg.go.dev/github.com/pocketbase/pocketbase/tools/security) package — no external crypto dependencies needed.

### Key Format

```
┌──────────┬──────────────────────────────────────────┐
│  prefix  │   security.RandomString(KeyLength)        │
│  "pbk_"  │  e.g. "aB3xK9mW2qR7tY5vN8cL1pF4dG6hJ0sA" │
└──────────┴──────────────────────────────────────────┘
```

Full example: `pbk_aB3xK9mW2qR7tY5vN8cL1pF4dG6hJ0sA`

### Hashing Strategy

- **Algorithm**: `security.SHA256()` — returns hex-encoded SHA-256 hash
- **Random generation**: `security.RandomString()` — cryptographically random `[A-Za-z0-9]+`
- **Constant-time comparison**: `security.Equal()` — available for in-memory hash comparison (not used for DB lookups)
- **Storage**: hex-encoded SHA-256 hash in the `key_hash` column
- **Lookup**: incoming key → `security.SHA256(rawKey)` → `SELECT ... WHERE key_hash = ?`
- **Partial prefix storage**: The prefix part (`pbk_`) is stored in a separate `key_prefix` column for quick filtering/auditing without knowing the full key

```go
package apikeyauth

import (
    "fmt"
    "strings"

    "github.com/pocketbase/pocketbase/tools/security"
)

// generateAPIKey creates a new API key with the given prefix and random character length.
// Returns the full raw key (prefix + RandomString) and its SHA-256 hash.
// Uses PocketBase's security.RandomString (crypto/rand backed) and security.SHA256.
func generateAPIKey(prefix string, keyLength int) (rawKey string, hash string) {
    rawKey = prefix + security.RandomString(keyLength)
    hash = security.SHA256(rawKey)
    return rawKey, hash
}

// validateKeyPrefix checks that the prefix is valid:
// - 3–8 characters
// - alphanumeric + trailing underscore (mandatory)
// - must end with underscore for readability
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
```

---

## 3. Collection Schema

### `desiredCollection(cfg Config) *core.Collection`

The `api_keys` collection schema. Each user can have multiple keys, each identified by a user-defined `name`.

```go
func desiredCollection(cfg Config) *core.Collection {
    c := core.NewCollection(core.CollectionTypeBase, cfg.CollectionName)
    c.Id = cfg.CollectionID // stable ID for first-time creation

    // --- Fields ---

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

    // --- Indexes ---

    c.Indexes = append(c.Indexes,
        // Fast lookup by hash (primary lookup path)
        "CREATE UNIQUE INDEX idx_api_key_hash ON {{NAME}} (key_hash)",
        // Prevent duplicate names per user
        "CREATE UNIQUE INDEX idx_api_key_user_name ON {{NAME}} (user, name)",
    )

    // --- API Rules (for the built-in record API) ---
    // Only the owner can list/view/update/delete their own keys
    c.ListRule   = types.Pointer("user = @request.auth.id")
    c.ViewRule   = types.Pointer("user = @request.auth.id")
    c.CreateRule = types.Pointer("user = @request.auth.id")
    c.UpdateRule = types.Pointer("user = @request.auth.id")
    c.DeleteRule = types.Pointer("user = @request.auth.id")

    return c
}
```

### Field summary

| Field | Type | Purpose |
|---|---|---|
| `name` | text(100) | Human-readable label set by the user |
| `key_hash` | text(64) | SHA-256 hex of the full key |
| `key_prefix` | text(8) | Prefix portion (e.g. `pbk_`) for auditing |
| `user` | relation→users | Owner of this key |
| `disabled` | bool | Soft revocation |
| `expires_at` | date | Optional expiration |
| `created` | auto | PocketBase auto-managed |
| `updated` | auto | PocketBase auto-managed |

---

## 4. `Register()` — Updated

```go
// Register wires the plugin into a PocketBase app. Must be called before app.Start().
// Accepts zero or more functional Option arguments.
func Register(app core.App, opts ...Option) {
    cfg := DefaultConfig()
    for _, opt := range opts {
        opt(&cfg)
    }

    if err := validateKeyPrefix(cfg.KeyPrefix); err != nil {
        panic(fmt.Sprintf("apikeyauth: invalid key prefix: %v", err))
    }

    // OnBootstrap: ensure the api_keys collection exists / is migrated
    app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
        if err := e.Next(); err != nil {
            return err
        }
        return ensureCollection(app, cfg)
    })

    // OnServe: register middleware + API routes
    app.OnServe().BindFunc(func(se *core.ServeEvent) error {
        se.Router.Use(apiKeyAuthMiddleware(app, cfg))

        // Mount the key creation endpoint (other operations via PocketBase CRUD)
        se.Router.POST(cfg.ApiPath, createAPIKeyHandler(app, cfg), apis.RequireAuth())

        return se.Next()
    })
}
```

---

## 5. Middleware — Updated for Hashing & Expiry

```go
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
            app.Logger().Debug("API key rejected: invalid prefix",
                "prefix", cfg.KeyPrefix)
            return e.Next()
        }

        // Hash the incoming key and look up by hash
        keyHash := security.SHA256(rawKey)
        keyRecord, err := app.FindFirstRecordByData(cfg.CollectionName, "key_hash", keyHash)
        if err != nil {
            app.Logger().Debug("API key not found or invalid", "error", err)
            return e.Next()
        }

        // Check if key is disabled (revoked)
        if keyRecord.GetBool("disabled") {
            app.Logger().Debug("API key is disabled (revoked)",
                "keyId", keyRecord.Id)
            return e.Next()
        }

        // Check expiry
        if !keyRecord.GetDateTime("expires_at").IsZero() {
            if keyRecord.GetDateTime("expires_at").Time().Before(time.Now()) {
                app.Logger().Debug("API key has expired",
                    "keyId", keyRecord.Id,
                    "expiresAt", keyRecord.GetDateTime("expires_at"))
                return e.Next()
            }
        }

        // Resolve the associated user
        userId := keyRecord.GetString("user")
        userRecord, err := app.FindAuthRecordById("users", userId)
        if err != nil {
            app.Logger().Debug("API key user not found",
                "error", err, "userId", userId)
            return e.Next()
        }

        e.Auth = userRecord
        return e.Next()
    }
}
```

---

## 6. API Handler (Create Only)

Other operations (list, view, update, disable, delete) are performed through PocketBase's built-in Record API (`/api/collections/api_keys/records`). The collection's API rules (section 3) enforce that users can only operate on their own keys.

### `POST /api/api-key` — Create a new API key

**Request body (JSON):**
```json
{
    "name": "My CI Server",
    "expires_at": "2027-01-01T00:00:00Z"   // optional
}
```

**Response (201 Created):**
```json
{
    "id": "abc123",
    "name": "My CI Server",
    "key": "pbk_dGhpcyBpcyBhIHNlY3JldCBrZXk",
    "key_prefix": "pbk_",
    "user": "user123",
    "disabled": false,
    "expires_at": "2027-01-01T00:00:00Z",
    "created": "2026-07-17T12:00:00Z",
    "updated": "2026-07-17T12:00:00Z"
}
```

> **Critical**: The raw `key` field is returned **only once** in this response. It is never stored in plaintext — only `key_hash` is persisted. There is no endpoint to retrieve a lost key; the user must create a new one.

**Implementation:**

```go
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

        if strings.TrimSpace(body.Name) == "" {
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

        // Generate the key (no error possible — security.RandomString always succeeds)
        rawKey, keyHash := generateAPIKey(cfg.KeyPrefix, cfg.KeyLength)

        // Find the collection
        collection, err := app.FindCollectionByNameOrId(cfg.CollectionName)
        if err != nil {
            return e.InternalServerError("api_keys collection not found", err)
        }

        // Create the record
        record := core.NewRecord(collection)
        record.Set("name", strings.TrimSpace(body.Name))
        record.Set("key_hash", keyHash)
        record.Set("key_prefix", cfg.KeyPrefix)
        record.Set("user", e.Auth.Id)
        record.Set("disabled", false)

        if body.ExpiresAt != "" {
            t, err := time.Parse(time.RFC3339, body.ExpiresAt)
            if err != nil {
                return e.BadRequestError("invalid expires_at format, use ISO 8601", err)
            }
            record.Set("expires_at", t)
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
```

---

## 7. `ensureCollection()` — Updated

```go
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

    // Avoid expensive no-op save
    if existing.Fields.String() == desired.Fields.String() &&
        existing.Indexes.String() == desired.Indexes.String() {
        return nil
    }

    return app.Save(desired) // SyncRecordTableSchema runs automatically
}
```

---

## 8. Key Generation & Validation Flow (Visual)

```
┌──────────────────────────────────────────────────────────────┐
│                    KEY CREATION (POST /api/api-key)           │
│                                                              │
│  1. User sends: { "name": "My Key", "expires_at": "..." }    │
│  2. Server calls generateAPIKey("pbk_", 43)                  │
│     → rawKey  = "pbk_" + security.RandomString(43)           │
│     → keyHash = security.SHA256(rawKey)                      │
│  3. Store in DB: { name, key_hash, key_prefix, user, ... }   │
│  4. Return to user: { ..., "key": "<rawKey>" } ← ONE TIME    │
│                                                              │
│  ⚠️  rawKey is NEVER stored; only key_hash is persisted      │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│                    AUTHENTICATION (every request)             │
│                                                              │
│  1. Client sends header: X-API-Key: pbk_dGhpcyBpcy...       │
│  2. Middleware checks prefix "pbk_" — reject early if wrong  │
│  3. Hash incoming key: security.SHA256("pbk_dGhpcyBpcy...")  │
│  4. DB lookup: SELECT * FROM api_keys WHERE key_hash = ?     │
│  5. Check: disabled? expires_at in past? → skip              │
│  6. Resolve user → set e.Auth                                │
└──────────────────────────────────────────────────────────────┘
```

---

## 9. Migration Flow

```
┌──────────────────┐
│  Plugin v1.0     │  desiredCollection() defines:
│  First boot      │    name, key_hash, key_prefix, user,
│                  │    disabled, expires_at
│                  │  → FindCollectionByNameOrId fails
│                  │  → app.Save(desired) creates table + indexes
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Plugin v1.1     │  desiredCollection() adds new_field
│  Boot            │  → FindCollectionByNameOrId succeeds
│                  │  → Fields.String() differs → app.Save(desired)
│                  │  → SyncRecordTableSchema: ADD COLUMN new_field
│                  │  → Indexes recreated
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Plugin v1.2     │  desiredCollection() unchanged
│  Boot            │  → Fields.String() match → no-op
└──────────────────┘
```

---

## 10. Complete API Surface

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/api-key` (configurable) | `RequireAuth` | Create a new API key. Returns raw key **once**. |
| *(middleware)* | `*` | none | Reads configured header, authenticates via API key if present. |

> **Other operations** (list, view, update, disable, delete) are handled through PocketBase's built-in Record API at `/api/collections/api_keys/records`. The collection's API rules (`user = @request.auth.id`) enforce ownership.

---

## 11. Design Decisions & Rationale

| Decision | Rationale |
|---|---|
| `Register(app, ...opts)` over `init()` | No global state; testable; explicit; follows PocketBase convention |
| Functional options pattern for config | Extensible; backwards-compatible; zero-config works out of the box |
| `security.SHA256` + `security.RandomString` | Uses PocketBase's own audited crypto; zero external dependencies; `RandomString` is crypto/rand backed |
| `security.Equal` for constant-time comparison | Available for in-memory hash checks; prevents timing side-channels |
| Raw key returned only at creation | Industry standard (GitHub PATs, Stripe API keys); prevents key leaks from DB dumps |
| `key_prefix` stored alongside `key_hash` | Enables early rejection in middleware without DB hit; aids auditing (e.g. "revoke all `pbk_` keys") |
| Prefix check in middleware before DB lookup | Rejects malformed keys cheaply; reduces DB load from random probes |
| `disabled` field for revocation | Non-destructive; preserves audit trail; mirrors PocketBase's own user `verified` pattern |
| `expires_at` as optional datetime | Simple; checked in middleware; no background job needed |
| Unique index on `(user, name)` | Prevents duplicate names per user; enforces user-friendly naming |
| `unlimited` max keys by default (`MaxKeysPerUser: 0`) | Backwards compatible; opt-in throttling |
| API route at configurable path, defaults to `/api/api-key` | Consumer-controlled; avoids route conflicts |
| Other operations via PocketBase CRUD | No need to duplicate list/view/update/delete handlers; PocketBase's Record API + API rules handle ownership enforcement |
| `desiredCollection()` as schema source of truth | Single place to update; no SQL migration files; no version tracking |
| Silently skip invalid keys (no error response) | Mirrors `loadAuthToken()` behavior; lets downstream `RequireAuth` decide the 401 |
| Configurable header name (not `Authorization`) | Avoids collision with JWT; customer can choose their own header convention |

---

## 12. Implementation Order (Suggested)

| Phase | Files | What |
|---|---|---|
| **Phase 1** | `apikeyauth.go`, `collection.go` | `Config`, `Option` funcs, `desiredCollection()`, `ensureCollection()`, `Register()` |
| **Phase 2** | `keygen.go` | `generateAPIKey()`, `validateKeyPrefix()` |
| **Phase 3** | `middleware.go` | `apiKeyAuthMiddleware()` with hashing, prefix check, disabled check, expiry check |
| **Phase 4** | `handlers.go` | `POST /api/api-key` (create only) |
| **Phase 5** | `apikeyauth_test.go` | Unit tests for keygen, middleware, handlers; integration test with test app |
| **Phase 6** | `README.md` | Usage docs, API docs, examples |
