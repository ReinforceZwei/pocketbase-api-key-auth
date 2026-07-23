// Package apikeyauth provides API key authentication for PocketBase.
//
// Register the plugin with a PocketBase app to add API key support:
//
//	apikeyauth.Register(app)
//	apikeyauth.Register(app, apikeyauth.WithKeyPrefix("myapp_"))
package apikeyauth

import (
	"fmt"
	"log"

	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
)

// Config holds all customizable settings for the plugin.
// All fields are optional — defaults are applied via [DefaultConfig].
type Config struct {
	// CollectionName is the name of the collection that stores API keys.
	// Default: "apiKeys"
	CollectionName string

	// CollectionID is the stable ID for the apiKeys collection.
	// Changing this after initial deployment is NOT recommended.
	// Default: "pbc_apikeys_plugin"
	CollectionID string

	// HeaderName is the HTTP header to read the API key from.
	// Default: "X-API-Key"
	HeaderName string

	// ApiPath is the route path for the key creation endpoint.
	// Default: "/api/api-key"
	ApiPath string

	// KeyPrefix is prepended to every generated API key.
	// Must be 3–8 alphanumeric characters + trailing underscore.
	// Default: "pbk_"
	KeyPrefix string

	// KeyLength is the number of random characters in the key (after the prefix).
	// Uses [security.RandomString] — result matches [A-Za-z0-9]+.
	// Default: 43 (combined with "pbk_" gives ~47 chars)
	KeyLength int

	// MaxKeysPerUser limits how many active keys a single user can have.
	// 0 = unlimited. Default: 0
	MaxKeysPerUser int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		CollectionName: "apiKeys",
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

// Register wires the plugin into a PocketBase app.
// Must be called once before app.Start().
// Accepts zero or more functional [Option] arguments.
func Register(app core.App, opts ...Option) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	if err := validateConfig(cfg); err != nil {
		log.Fatalf("apikeyauth: invalid config: %v", err)
	}

	// OnBootstrap: ensure the apiKeys collection exists / is migrated
	app.OnBootstrap().BindFunc(func(e *core.BootstrapEvent) error {
		if err := e.Next(); err != nil {
			return err
		}
		return ensureCollection(app, cfg)
	})

	// OnServe: register middleware + API routes
	app.OnServe().BindFunc(func(se *core.ServeEvent) error {
		// Global middleware — runs on every request, checks for API key
		se.Router.BindFunc(apiKeyAuthMiddleware(app, cfg))

		// Key creation endpoint
		se.Router.POST(cfg.ApiPath, createAPIKeyHandler(app, cfg)).
			Bind(apis.RequireAuth())

		// Key update endpoint (only name, disabled, expires_at are allowed)
		se.Router.PATCH(cfg.ApiPath+"/{id}", updateAPIKeyHandler(app, cfg)).
			Bind(apis.RequireAuth())

		// Key deletion endpoint
		se.Router.DELETE(cfg.ApiPath+"/{id}", deleteAPIKeyHandler(app, cfg)).
			Bind(apis.RequireAuth())

		return se.Next()
	})
}

// validateConfig checks that the plugin configuration is safe and valid.
func validateConfig(cfg Config) error {
	if err := validateKeyPrefix(cfg.KeyPrefix); err != nil {
		return fmt.Errorf("key prefix: %w", err)
	}
	if cfg.KeyLength < MinKeyLength {
		return fmt.Errorf("key length must be at least %d, got %d", MinKeyLength, cfg.KeyLength)
	}
	return nil
}
