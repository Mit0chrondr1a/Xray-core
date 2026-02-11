package buf

import "context"

type arenaKey struct{}

// ContextWithArena returns a new context with the given Arena attached.
// The arena should be closed when the connection is done.
func ContextWithArena(ctx context.Context, a *Arena) context.Context {
	return context.WithValue(ctx, arenaKey{}, a)
}

// ArenaFromContext returns the Arena from the context, or nil if none.
func ArenaFromContext(ctx context.Context) *Arena {
	a, _ := ctx.Value(arenaKey{}).(*Arena)
	return a
}
