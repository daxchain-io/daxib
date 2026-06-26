package tools

import (
	"reflect"

	"github.com/daxchain-io/daxib/internal/domain"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// schema.go is the §6.2 schema-inference seam. The MCP tool schemas are INFERRED
// from the SAME domain request/result structs the CLI binds — there are NO
// hand-written duplicate schemas, so CLI/MCP cannot drift (the golden test pins
// the realized surface). Inference is done by the SAME engine the SDK uses
// internally (github.com/google/jsonschema-go), driven explicitly only so we can
// correct the value types whose Go KIND disagrees with their JSON wire form.
//
// WHY THIS FILE EXISTS (the value-type fix). The SDK's default inference types a
// Go value by its kind: domain.Duration is a struct → JSON "object". But it
// MARSHALS as a STRING ("30m0s") via its MarshalJSON. The SDK validates a tool's
// typed In/Out against the inferred schema at call time, so with the default
// mapping every input carrying a Duration (tx_wait.timeout, send.wait.timeout) is
// rejected with `has type "string", want "object"`. Unlike daxie, daxib's amounts
// are already plain strings and its addresses are plain strings, so domain.Duration
// is the ONLY value type that needs correcting — there are no [N]byte address/hash
// types and no []byte fields on the tx surface.
//
// THE FIX (still inference, not hand-written schemas). jsonschema.For accepts
// ForOptions.TypeSchemas — a per-type override applied BEFORE kind-based inference.
// We map domain.Duration to {type:"string"}, run the SAME inference over the SAME
// domain structs (struct tags, required/optional, descriptions all preserved), and
// set the result as the tool's explicit InputSchema/OutputSchema. The golden test
// pins every realized schema so this can never silently change.

// valueTypeSchemas overrides the JSON-schema inference for the daxib value types
// whose Go kind disagrees with their encoding/json wire form. time.Time / big.Int
// are already handled by jsonschema-go's built-in map; these two are the ones it
// does not know about. Keyed by reflect.Type so the override applies wherever the
// type appears (top level, a struct field, or a nested struct field).
var valueTypeSchemas = map[reflect.Type]*jsonschema.Schema{
	// domain.Duration marshals as a Go duration string ("30m0s") via its MarshalJSON
	// (used in WaitOpts.Timeout / WaitRequest.Timeout).
	reflect.TypeFor[domain.Duration](): {Type: "string"},
	// FeeQuotesResult.ByTarget is a map[int]int64. jsonschema-go rejects a non-string
	// map key outright ("unsupported map key type int"), but encoding/json MARSHALS an
	// int-keyed map as a JSON OBJECT with the keys stringified ({"1":5,"6":3}). Without
	// this override the `fee` tool's output schema cannot be inferred at all (a build-
	// time panic). The wire form is an object of confirmation-target → sat/vB, so we
	// type it as {object, additionalProperties:{integer}} — the schema the marshaled
	// value actually validates against.
	reflect.TypeFor[map[int]int64](): {
		Type:                 "object",
		AdditionalProperties: &jsonschema.Schema{Type: "integer"},
	},
}

// inferSchema returns the JSON schema for T, inferred from T's Go type by the SAME
// engine the MCP SDK uses, with the value-type overrides applied. It is the ONE
// place every tool's In/Out schema is produced, so the correction is uniform and
// the golden test pins a single, consistent surface.
func inferSchema[T any]() *jsonschema.Schema {
	s, err := jsonschema.For[T](&jsonschema.ForOptions{TypeSchemas: valueTypeSchemas})
	if err != nil {
		// Inference of a fixed, compile-time-known domain struct cannot fail at
		// runtime; a failure here is a programming error (a new tool bound a type the
		// engine rejects) and must surface loudly at server-build time. Registration
		// runs once at New(svc); this never reaches a client.
		panic("mcpserver/tools: schema inference for " + reflect.TypeFor[T]().String() + ": " + err.Error())
	}
	return s
}

// withSchemas stamps the inferred input and output schemas onto a tool definition.
// The SDK uses a non-nil InputSchema/OutputSchema verbatim (resolving + validating
// against it) instead of running its own uncorrected inference — so setting these
// is what routes the SDK through OUR value-type-correct schema. Returns the same
// *mcp.Tool for chaining in the AddTool call sites.
func withSchemas[In, Out any](def *mcp.Tool) *mcp.Tool {
	def.InputSchema = inferSchema[In]()
	def.OutputSchema = inferSchema[Out]()
	return def
}
