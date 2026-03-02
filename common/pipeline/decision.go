package pipeline

// Path enumerates pipeline data-plane choices.
type Path string

const (
	PathUserspace Path = "userspace"
	PathSplice    Path = "splice"
	PathSockmap   Path = "sockmap"
)

// DecisionSnapshot carries per-connection pipeline outcomes for logging/telemetry.
type DecisionSnapshot struct {
	Path                Path
	Reason              string
	Caps                CapabilitySummary
	SpliceBytes         int64
	SpliceDurationNs    int64
	UserspaceBytes      int64
	UserspaceDurationNs int64
	SockmapSuccess      bool
	ErrorClass          string
	Kind                string // optional: component-specific tag (e.g., proxy, xhttp)
}
