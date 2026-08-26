package server

import (
	"errors"
	"net/http"
	"time"
)

var errNilSchemaResolver = errors.New("server: schema resolver must not be nil")

// SchemaResolution is the outcome of resolving the schemas a request is
// permitted to access, along with the time at which that permission expires.
// A zero ExpiresAt means the resolution does not expire.
type SchemaResolution struct {
	AllowedSchemas []string
	ExpiresAt      time.Time
}

// SchemaResolver resolves the schemas a request is permitted to access. It is
// the generic seam that lets JWT-derived authorization reach the query path
// without coupling this package to any particular token format.
type SchemaResolver interface {
	ResolveSchemas(*http.Request) (SchemaResolution, error)
}

// SchemaResolverFunc adapts a function to a SchemaResolver.
type SchemaResolverFunc func(*http.Request) (SchemaResolution, error)

func (f SchemaResolverFunc) ResolveSchemas(r *http.Request) (SchemaResolution, error) { return f(r) }

// WithSchemaResolver configures resolver as the source of allowed schemas and
// their expiry, taking priority over WithSchemaMatchHeaders.
func WithSchemaResolver(resolver SchemaResolver) Option {
	return optionFunc(func(cfg *config) error {
		if resolver == nil || isNilValue(resolver) {
			return errNilSchemaResolver
		}
		cfg.schemaResolver = resolver
		return nil
	})
}
