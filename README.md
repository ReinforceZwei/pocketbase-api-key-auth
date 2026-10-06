# pocketbase-api-key-auth

API key authentication plugin for [PocketBase](https://pocketbase.io/) v0.39+.

Authenticate users via a configurable HTTP header (default `X-API-Key`) instead of / in addition to JWT tokens.  
Keys are hashed with SHA-256 before storage — the raw key is returned **only once** at creation.

Keys are ordinary records in an `apiKeys` collection: they are created, listed, updated and deleted
through PocketBase's built-in Record API (`/api/collections/apiKeys/records`), so the REST API, the
JS SDK and the batch API all work as usual. The plugin attaches the key-specific logic (generation,
hashing, ownership, immutable fields) to those endpoints with PocketBase's
[request hooks](https://pocketbase.io/docs/go-event-hooks/#request-hooks).

---

## Installation

```
go get github.com/ReinforceZwei/pocketbase-api-key-auth
```

Requires Go 1.25+ and PocketBase v0.39+.

---

## Quick Start

```go
package main

import (
    "log"

    "github.com/pocketbase/pocketbase"
    "github.com/ReinforceZwei/pocketbase-api-key-auth"
)

func main() {
    app := pocketbase.New()

    // Zero-config: registers with sensible defaults
    apikeyauth.Register(app)

    if err := app.Start(); err != nil {
        log.Fatal(err)
    }
}
```

That's it. On first boot the `apiKeys` collection is auto-created. After that, create your first key
with `POST /api/collections/apiKeys/records` (see [API](#api) below).

---

## Configuration

All customization is done via functional options passed to `Register`. Every option is optional.

```go
apikeyauth.Register(app,
    apikeyauth.WithHeaderName("X-MyApp-Key"),   // HTTP header to read (default: "X-API-Key")
    apikeyauth.WithKeyPrefix("myapp_"),          // prefix for all generated keys (default: "pbk_")
    apikeyauth.WithKeyLength(50),                // random chars after prefix (default: 43)
    apikeyauth.WithCollectionName("app_keys"),   // collection name (default: "apiKeys")
    apikeyauth.WithCollectionID("pbc_mykeys"),   // stable collection ID (default: "pbc_apikeys_plugin")
    apikeyauth.WithMaxKeysPerUser(5),            // limit active keys per user, 0=unlimited (default: 0)
)
```

| Option | Default | Description |
|---|---|---|
| `WithHeaderName` | `"X-API-Key"` | HTTP header to read the API key from |
| `WithKeyPrefix` | `"pbk_"` | Prefix for all generated keys |
| `WithKeyLength` | `43` | Random `[A-Za-z0-9]` characters after prefix. Minimum: 32 |
| `WithCollectionName` | `"apiKeys"` | Name of the collection storing keys |
| `WithCollectionID` | `"pbc_apikeys_plugin"` | Stable ID for the collection |
| `WithMaxKeysPerUser` | `0` (unlimited) | Max active keys per user |

---

## API

The keys live in the `apiKeys` collection and are managed through PocketBase's built-in Record API.
Beyond the usual collection endpoints, the plugin adds:

- key generation and hashing on **create** — the raw key is returned in that one response,
- ownership enforcement and immutable-field protection on **update**,
- nothing extra on **list / view / delete** — the collection's API rules already scope them to the owner.

| Operation | Endpoint |
|---|---|
| Create a key | `POST /api/collections/apiKeys/records` |
| List your keys | `GET /api/collections/apiKeys/records` |
| View a key | `GET /api/collections/apiKeys/records/:id` |
| Update a key | `PATCH /api/collections/apiKeys/records/:id` |
| Delete a key | `DELETE /api/collections/apiKeys/records/:id` |
| Revoke (soft) | `PATCH` with `{"disabled": true}` |

All of them require a valid PocketBase auth token (JWT) and are additionally restricted by the
collection's API rules, so a user can only ever see and touch their own keys.

### Field reference

| Field | On create | On update | Notes |
|---|---|---|---|
| `name` | **required** | mutable | trimmed; must be unique per user |
| `user` | **required** | immutable | must be your own id; the plugin also forces it to the caller |
| `expires_at` | optional | mutable | ISO 8601 (`2027-01-01T00:00:00Z`) or PocketBase format (`2027-01-01 00:00:00.000Z`); send `""` to clear |
| `disabled` | ignored (forced `false`) | mutable | soft revocation |
| `key` | — | immutable | the raw key, returned once on create only |
| `key_hash` | ignored | immutable | SHA-256 hex, hidden from all responses |
| `key_prefix` | ignored | immutable | prefix of the key, kept for auditing |
| `id` / `created` / `updated` | — | immutable | managed by PocketBase |

`user`, `key_hash`, `key_prefix`, `key`, `id`, `created` and `updated` are rejected with `400` if
they appear in an update request.

### Creating a key

**Request** — `POST /api/collections/apiKeys/records`

```json
{
    "name": "My CI Server",
    "user": "user123",
    "expires_at": "2027-01-01T00:00:00Z"
}
```

`user` must be the caller's own id: the collection's create rule is
`@request.auth.id != '' && user = @request.auth.id`, so creating a key for somebody else is rejected
before the key is generated.

**Response `200`** — the created record, plus the raw key **exactly once**:

```json
{
    "id": "abc123",
    "collectionId": "pbc_apikeys_plugin",
    "collectionName": "apiKeys",
    "name": "My CI Server",
    "key": "pbk_aB3xK9mW2qR7tY5vN8cL1pF4dG6hJ0sA",
    "key_prefix": "pbk_",
    "user": "user123",
    "disabled": false,
    "expires_at": "2027-01-01 00:00:00.000Z",
    "created": "2026-07-20 12:00:00.000Z",
    "updated": "2026-07-20 12:00:00.000Z"
}
```

The `key` is attached as record custom data: it is serialized in this response but never written to
the database, and no later read of the record will include it.

**Errors**

| Case | Response |
|---|---|
| missing / blank `name` | `400` with a `name` field validation error |
| missing or foreign `user` | `400` (create rule) |
| no auth token | `400` (create rule) |
| `expires_at` not parseable | `400 invalid expires_at format, use ISO 8601` |
| duplicate `name` for the same user | `400` (unique index) |
| more than `MaxKeysPerUser` active keys | `400 Maximum of N active API keys reached` |

### Updating a key

**Request** — `PATCH /api/collections/apiKeys/records/:id`

```json
{
    "name": "Renamed Key",
    "disabled": true,
    "expires_at": "2027-06-01 00:00:00.000Z"
}
```

**Response `200`**: the updated record. Immutable fields are rejected with
`400 field "user" is immutable and cannot be changed`, and another user's key is not reachable at
all (`404`).

### Deleting a key

**Request** — `DELETE /api/collections/apiKeys/records/:id`

**Response `204`** with an empty body. Only the owner can delete their own key.

### Using the JS SDK

```js
// create — the raw key is in the response and is never retrievable again
const created = await pb.collection('apiKeys').create({
    name: 'CI Server',
    user: pb.authStore.record.id,          // must be your own id
    expires_at: '2027-01-01 00:00:00.000Z', // optional
});
const rawKey = created.key;                 // pbk_…

// list / view
const keys = await pb.collection('apiKeys').getFullList({ sort: '-created' });

// rename and revoke
await pb.collection('apiKeys').update(created.id, { name: 'Renamed' });
await pb.collection('apiKeys').update(created.id, { disabled: true });

// delete
await pb.collection('apiKeys').delete(created.id);
```

### Authenticating requests

Send the key in the configured header (default `X-API-Key`):

```
GET /api/collections/posts/records HTTP/1.1
X-API-Key: pbk_aB...J0sA
```

The middleware runs after PocketBase's JWT auth. If a valid JWT token is already present, the API key is ignored. If the key is invalid, expired, or disabled, the request continues unauthenticated — downstream `RequireAuth` middleware decides the 401 response.

---

## Key Format & Security

Each key has two parts:

```
┌──────────┬──────────────────────────────────────────┐
│  prefix  │   RandomString(KeyLength)                 │
│  "pbk_"  │  e.g. "aB3xK9mW2qR7tY5vN8cL1pF4dG6hJ0sA" │
└──────────┴──────────────────────────────────────────┘
```

- **Prefix** — configurable, 3–8 alphanumeric + trailing underscore (e.g. `pbk_`, `myapp_`). Used for fast rejection in the middleware and for auditing.
- **Body** — `[A-Za-z0-9]+` generated by PocketBase's `security.RandomString()` (crypto/rand backed).
- **Hashing** — SHA-256 via `security.SHA256()`. Only the hex-encoded hash is stored in `key_hash`. Raw key is never persisted.

| Field | Type | Purpose |
|---|---|---|
| `key_hash` | text(64) | SHA-256 hex of the full key (hidden from API responses) |
| `key_prefix` | text(8) | Prefix portion for early rejection + auditing |
| `name` | text(100) | User-defined label |
| `user` | relation→users | Key owner |
| `disabled` | bool | Soft revocation |
| `expires_at` | date | Optional expiration |

---

## ⚠️ Changing the Key Prefix

The prefix check (`strings.HasPrefix`) in the middleware is the **first gate** for every request. If you change `KeyPrefix` after keys have already been issued:

- **All existing keys become invalid** — they carry the old prefix and will be rejected before any DB lookup.
- The `key_prefix` field on existing records will still show the old value (cosmetic only).

If you have existing keys and need to change the prefix, you have two options:

1. **Re-issue all keys** — create new keys with the new prefix and distribute them, then disable the old ones.
2. **Don't change the prefix** — choose the prefix upfront and stick with it for the lifetime of your application.

---

## Plugin Design

The plugin follows PocketBase's own conventions — explicit `Register(app)` call, no global state, and
`desiredCollection()` as the schema source of truth for automatic migrations. No custom routes are
mounted: the CRUD surface is intercepted with the `OnRecordCreateRequest` / `OnRecordUpdateRequest`
request hooks, which run after the request body has been loaded into the record but before it is
validated and saved.

**How schema changes work:**  
When you upgrade to a new plugin version that adds/modifies collection fields or API rules,
`ensureCollection()` diffs the existing collection against `desiredCollection()` and calls `app.Save()`
which internally runs `SyncRecordTableSchema` — adding columns, recreating indexes, etc. No SQL
migration files needed.

See [`api-key-plugin-design.md`](api-key-plugin-design.md) for the full design document.

---

## Development

### Prerequisites

- Go 1.25+
- PocketBase v0.39+

### Setup

```
git clone https://github.com/ReinforceZwei/pocketbase-api-key-auth
cd pocketbase-api-key-auth
go mod download
```

### Run tests

```
go test -v -count=1 ./...
```

38 test functions (87 cases) cover: key generation, prefix validation, config validation (including
minimum key length), collection schema, `ensureCollection` bootstrap/no-op/migration of a legacy
schema, middleware authentication (valid key, disabled key, wrong prefix, nonexistent key, JWT skip,
guest pass-through), creating keys through the built-in API (success, one-time raw key, hidden
`key_hash`, server-owned fields, name/owner validation, guest rejection, duplicate names, expiry
formats, `MaxKeysPerUser`, superuser creation on behalf of a user), updating keys (rename, disable,
expiry, immutable fields, `key_hash` spoof attempts, empty name, ownership and auth), deleting keys
(owner, other user, guest), the batch API, and an end-to-end create → authenticate → revoke flow.

### Project structure

```
├── apikeyauth.go            # Config, Option funcs, Register(), validateConfig()
├── collection.go            # desiredCollection(), ensureCollection()
├── keygen.go                # generateAPIKey(), validateKeyPrefix(), MinKeyLength
├── middleware.go             # apiKeyAuthMiddleware()
├── hooks.go                  # OnRecordCreateRequest / OnRecordUpdateRequest hooks
├── apikeyauth_test.go       # Unit + integration tests
├── api-key-plugin-design.md # Full design document
├── README.md
├── go.mod
└── go.sum
```

---

## Releasing

This is a Go library — follow standard module versioning with git tags.

### Steps

1. **Ensure tests pass:**
   ```bash
   go test -count=1 ./...
   ```

2. **Tag and push:**
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```

3. **Consumers install via:**
   ```bash
   go get github.com/ReinforceZwei/pocketbase-api-key-auth@v0.1.0
   ```

### Version compatibility

| Plugin version | PocketBase version | Go version |
|---|---|---|
| v0.x | v0.39+ | 1.25+ |

The plugin uses PocketBase's own `tools/security` and `tools/types` packages with no external crypto dependencies, so compatibility is tied to the PocketBase minor version.
