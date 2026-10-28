// Package constant contains constants definitions
//
//nolint:revive // this package does not require comment on every line
package constant

// ContextKey is used for context keys
type ContextKey string

const ContextKeyLogger = ContextKey("logger")

const LogKeyError = "error"
