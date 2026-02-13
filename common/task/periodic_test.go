package task_test

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	. "github.com/xtls/xray-core/common/task"
)

func TestPeriodicTaskStop(t *testing.T) {
	const interval = 20 * time.Millisecond
	var value atomic.Int32
	task := &Periodic{
		Interval: interval,
		Execute: func() error {
			value.Add(1)
			return nil
		},
	}

	waitForAtLeast := func(target int32, timeout time.Duration) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for value.Load() < target {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for value >= %d, got %d", target, value.Load())
			}
			time.Sleep(interval / 4)
		}
	}

	common.Must(task.Start())
	waitForAtLeast(3, 250*time.Millisecond)

	common.Must(task.Close())
	stopped := value.Load()
	time.Sleep(3 * interval)
	if got := value.Load(); got != stopped {
		t.Fatalf("expected periodic task to stop at %d, got %d", stopped, got)
	}

	common.Must(task.Start())
	waitForAtLeast(stopped+2, 250*time.Millisecond)
	common.Must(task.Close())
}
