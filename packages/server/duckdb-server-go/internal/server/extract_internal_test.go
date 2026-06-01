package server

import (
	"errors"
	"testing"
)

// TestWrapSchemaError_SchemaVariant verifies that a schema-access denial produces
// a *schemaForbiddenError whose Schema field is bare (no quotes, no struct brace dump).
func TestWrapSchemaError_SchemaVariant(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantSchema string // empty string means: expect non-schemaForbiddenError passthrough
	}{
		{
			name:       "schema variant — bare schema name",
			input:      "query: validation failed for query: access denied: unauthorized access to schema 'bookings'",
			wantSchema: "bookings",
		},
		{
			name:       "empty-schema table variant — bare table name",
			input:      "query: validation failed for query: access denied: unauthorized access to table 'orders' with empty schema",
			wantSchema: "orders",
		},
		{
			name:       "unrelated error passes through unchanged",
			input:      "some other db error",
			wantSchema: "", // signals passthrough
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := wrapSchemaError(errors.New(tt.input))

			if tt.wantSchema == "" {
				// Expect the error to pass through — NOT a *schemaForbiddenError.
				var sfErr *schemaForbiddenError
				if errors.As(err, &sfErr) {
					t.Errorf("expected passthrough, got schemaForbiddenError{Schema:%q}", sfErr.Schema)
				}
				return
			}

			var sfErr *schemaForbiddenError
			if !errors.As(err, &sfErr) {
				t.Fatalf("expected *schemaForbiddenError, got %T: %v", err, err)
			}
			if sfErr.Schema != tt.wantSchema {
				t.Errorf("Schema = %q, want %q", sfErr.Schema, tt.wantSchema)
			}
		})
	}
}
