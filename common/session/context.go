package session

import (
	"context"
	_ "unsafe"

	"github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
)

//go:linkname IndependentCancelCtx context.newCancelCtx
func IndependentCancelCtx(parent context.Context) context.Context

const (
	inboundSessionKey         ctx.SessionKey = 1
	outboundSessionKey        ctx.SessionKey = 2
	contentSessionKey         ctx.SessionKey = 3
	isReverseMuxKey           ctx.SessionKey = 4  // is reverse mux
	sockoptSessionKey         ctx.SessionKey = 5  // used by dokodemo to only receive sockopt.Mark
	trackedConnectionErrorKey ctx.SessionKey = 6  // used by observer to get outbound error
	dispatcherKey             ctx.SessionKey = 7  // used by ss2022 inbounds to get dispatcher
	timeoutOnlyKey            ctx.SessionKey = 8  // mux context's child contexts to only cancel when its own traffic times out
	allowedNetworkKey         ctx.SessionKey = 9  // muxcool server control incoming request tcp/udp
	fullHandlerKey            ctx.SessionKey = 10 // outbound gets full handler
	mitmAlpn11Key             ctx.SessionKey = 11 // used by TLS dialer
	mitmServerNameKey         ctx.SessionKey = 12 // used by TLS dialer
	visionFlowKey             ctx.SessionKey = 13 // VLESS Vision flow active — skip kTLS-producing Rust paths
	dnsFlowClassKey           ctx.SessionKey = 14 // DNS flow class resolved once near dispatch
	dnsPlaneKey               ctx.SessionKey = 15 // DNS handling plane marker for telemetry
)

func ContextWithInbound(ctx context.Context, inbound *Inbound) context.Context {
	return context.WithValue(ctx, inboundSessionKey, inbound)
}

func InboundFromContext(ctx context.Context) *Inbound {
	if inbound, ok := ctx.Value(inboundSessionKey).(*Inbound); ok {
		return inbound
	}
	return nil
}

func ContextWithOutbounds(ctx context.Context, outbounds []*Outbound) context.Context {
	return context.WithValue(ctx, outboundSessionKey, outbounds)
}

func SubContextFromMuxInbound(ctx context.Context) context.Context {
	newOutbounds := []*Outbound{{}}

	content := ContentFromContext(ctx)
	newContent := Content{}
	if content != nil {
		newContent = *content
		// Clear attributes for sub-context; do not inherit mux parent's attributes
		newContent.Attributes = nil
	}
	return ContextWithContent(ContextWithOutbounds(ctx, newOutbounds), &newContent)
}

func OutboundsFromContext(ctx context.Context) []*Outbound {
	if outbounds, ok := ctx.Value(outboundSessionKey).([]*Outbound); ok {
		return outbounds
	}
	return nil
}

func ContextWithContent(ctx context.Context, content *Content) context.Context {
	return context.WithValue(ctx, contentSessionKey, content)
}

func ContentFromContext(ctx context.Context) *Content {
	if content, ok := ctx.Value(contentSessionKey).(*Content); ok {
		return content
	}
	return nil
}

func ContextWithIsReverseMux(ctx context.Context, isReverseMux bool) context.Context {
	return context.WithValue(ctx, isReverseMuxKey, isReverseMux)
}

func IsReverseMuxFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(isReverseMuxKey).(bool); ok {
		return val
	}
	return false
}

func ContextWithSockopt(ctx context.Context, s *Sockopt) context.Context {
	return context.WithValue(ctx, sockoptSessionKey, s)
}

func SockoptFromContext(ctx context.Context) *Sockopt {
	if sockopt, ok := ctx.Value(sockoptSessionKey).(*Sockopt); ok {
		return sockopt
	}
	return nil
}

func GetForcedOutboundTagFromContext(ctx context.Context) string {
	if ContentFromContext(ctx) == nil {
		return ""
	}
	return ContentFromContext(ctx).Attribute("forcedOutboundTag")
}

func SetForcedOutboundTagToContext(ctx context.Context, tag string) context.Context {
	if contentFromContext := ContentFromContext(ctx); contentFromContext == nil {
		ctx = ContextWithContent(ctx, &Content{})
	}
	ContentFromContext(ctx).SetAttribute("forcedOutboundTag", tag)
	return ctx
}

type TrackedRequestErrorFeedback interface {
	SubmitError(err error)
}

func SubmitOutboundErrorToOriginator(ctx context.Context, err error) {
	if errorTracker := ctx.Value(trackedConnectionErrorKey); errorTracker != nil {
		errorTracker := errorTracker.(TrackedRequestErrorFeedback)
		errorTracker.SubmitError(err)
	}
}

func TrackedConnectionError(ctx context.Context, tracker TrackedRequestErrorFeedback) context.Context {
	return context.WithValue(ctx, trackedConnectionErrorKey, tracker)
}

func ContextWithDispatcher(ctx context.Context, dispatcher routing.Dispatcher) context.Context {
	return context.WithValue(ctx, dispatcherKey, dispatcher)
}

func DispatcherFromContext(ctx context.Context) routing.Dispatcher {
	if dispatcher, ok := ctx.Value(dispatcherKey).(routing.Dispatcher); ok {
		return dispatcher
	}
	return nil
}

func ContextWithTimeoutOnly(ctx context.Context, only bool) context.Context {
	return context.WithValue(ctx, timeoutOnlyKey, only)
}

func TimeoutOnlyFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(timeoutOnlyKey).(bool); ok {
		return val
	}
	return false
}

func ContextWithAllowedNetwork(ctx context.Context, network net.Network) context.Context {
	return context.WithValue(ctx, allowedNetworkKey, network)
}

func AllowedNetworkFromContext(ctx context.Context) net.Network {
	if val, ok := ctx.Value(allowedNetworkKey).(net.Network); ok {
		return val
	}
	return net.Network_Unknown
}

func ContextWithFullHandler(ctx context.Context, handler outbound.Handler) context.Context {
	return context.WithValue(ctx, fullHandlerKey, handler)
}

func FullHandlerFromContext(ctx context.Context) outbound.Handler {
	if val, ok := ctx.Value(fullHandlerKey).(outbound.Handler); ok {
		return val
	}
	return nil
}

func ContextWithMitmAlpn11(ctx context.Context, alpn11 bool) context.Context {
	return context.WithValue(ctx, mitmAlpn11Key, alpn11)
}

func MitmAlpn11FromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(mitmAlpn11Key).(bool); ok {
		return val
	}
	return false
}

func ContextWithMitmServerName(ctx context.Context, serverName string) context.Context {
	return context.WithValue(ctx, mitmServerNameKey, serverName)
}

func MitmServerNameFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(mitmServerNameKey).(string); ok {
		return val
	}
	return ""
}

// ContextWithVisionFlow marks the context as carrying a VLESS Vision flow.
// Transport layers check this to skip kTLS-producing Rust native paths,
// since Vision strips outer TLS and kTLS is incompatible.
func ContextWithVisionFlow(ctx context.Context, vision bool) context.Context {
	return context.WithValue(ctx, visionFlowKey, vision)
}

// VisionFlowFromContext reports whether the context carries a Vision flow.
func VisionFlowFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(visionFlowKey).(bool); ok {
		return val
	}
	return false
}

// ContextWithDNSFlowClass stores the resolved DNS flow class in context.
func ContextWithDNSFlowClass(ctx context.Context, class DNSFlowClass) context.Context {
	return context.WithValue(ctx, dnsFlowClassKey, class)
}

// DNSFlowClassFromContext returns the DNS flow class if present.
func DNSFlowClassFromContext(ctx context.Context) DNSFlowClass {
	if val, ok := ctx.Value(dnsFlowClassKey).(DNSFlowClass); ok {
		return val
	}
	return DNSFlowClassUnset
}

// ContextWithDNSPlane stores DNS handling plane marker for telemetry.
func ContextWithDNSPlane(ctx context.Context, plane DNSPlane) context.Context {
	return context.WithValue(ctx, dnsPlaneKey, plane)
}

// DNSPlaneFromContext returns DNS handling plane marker if present.
func DNSPlaneFromContext(ctx context.Context) DNSPlane {
	if val, ok := ctx.Value(dnsPlaneKey).(DNSPlane); ok {
		return val
	}
	return DNSPlaneUnknown
}
