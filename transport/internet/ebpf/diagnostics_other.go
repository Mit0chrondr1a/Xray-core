//go:build !linux

package ebpf

import "context"

func logSockmapDeploymentDebug(context.Context, Capabilities, error) {}

func logAccelerationSummary(context.Context) {}
