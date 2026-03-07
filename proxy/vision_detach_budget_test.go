package proxy

import (
	"testing"
	"time"
)

func TestVisionDetachWaitBudgetDefaultsToMin(t *testing.T) {
	old := visionDetachBudgetNanos.Swap(0)
	t.Cleanup(func() {
		visionDetachBudgetNanos.Store(old)
	})

	if got := visionDetachWaitBudget(); got != visionDetachTimeoutMin {
		t.Fatalf("visionDetachWaitBudget() = %v, want %v", got, visionDetachTimeoutMin)
	}
}

func TestRecordVisionDetachBudgetClampsAndSmooths(t *testing.T) {
	old := visionDetachBudgetNanos.Swap(0)
	t.Cleanup(func() {
		visionDetachBudgetNanos.Store(old)
	})

	recordVisionDetachBudget(50 * time.Millisecond)
	if got := visionDetachWaitBudget(); got != visionDetachTimeoutMin {
		t.Fatalf("first budget = %v, want floor %v", got, visionDetachTimeoutMin)
	}

	recordVisionDetachBudget(900 * time.Millisecond)
	got := visionDetachWaitBudget()
	if got <= visionDetachTimeoutMin {
		t.Fatalf("smoothed budget = %v, want > %v after slower successful detach", got, visionDetachTimeoutMin)
	}
	if got > visionDetachTimeoutMax {
		t.Fatalf("smoothed budget = %v, want <= %v", got, visionDetachTimeoutMax)
	}
}

func TestVisionDetachWaitBudgetCapsAtMax(t *testing.T) {
	old := visionDetachBudgetNanos.Swap(int64(visionDetachTimeoutMax * 4))
	t.Cleanup(func() {
		visionDetachBudgetNanos.Store(old)
	})

	if got := visionDetachWaitBudget(); got != visionDetachTimeoutMax {
		t.Fatalf("visionDetachWaitBudget() = %v, want max %v", got, visionDetachTimeoutMax)
	}
}
