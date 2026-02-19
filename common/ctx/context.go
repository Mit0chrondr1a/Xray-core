package ctx

import "context"

type SessionKey int

// ID of a session.
type ID uint32

const (
	idSessionKey SessionKey = 0
)

type coneKey struct{}

// ContextWithCone returns a new context with the cone (connection reuse) flag set.
func ContextWithCone(ctx context.Context, cone bool) context.Context {
	return context.WithValue(ctx, coneKey{}, cone)
}

// ConeFromContext returns the cone flag from the context, or false if not set.
func ConeFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(coneKey{}).(bool)
	return v
}

// ContextWithID returns a new context with the given ID.
func ContextWithID(ctx context.Context, id ID) context.Context {
	return context.WithValue(ctx, idSessionKey, id)
}

// IDFromContext returns ID in this context, or 0 if not contained.
func IDFromContext(ctx context.Context) ID {
	if id, ok := ctx.Value(idSessionKey).(ID); ok {
		return id
	}
	return 0
}
