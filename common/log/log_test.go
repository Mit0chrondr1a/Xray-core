package log_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
)

type testLogger struct {
	value string
}

func (l *testLogger) Handle(msg log.Message) {
	l.value = msg.String()
}

func TestLogRecord(t *testing.T) {
	var logger testLogger
	log.RegisterHandler(&logger)

	ip := "8.8.8.8"
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Error,
		Content:  net.ParseAddress(ip),
	})

	if diff := cmp.Diff("[Error] "+ip, logger.value); diff != "" {
		t.Error(diff)
	}
}

func TestIsSeverityEnabledWithSeverityLogger(t *testing.T) {
	log.ReplaceWithSeverityLogger(log.Severity_Info)
	t.Cleanup(func() {
		log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter()))
	})

	if !log.IsSeverityEnabled(log.Severity_Error) {
		t.Fatal("expected error severity to be enabled at info level")
	}
	if !log.IsSeverityEnabled(log.Severity_Info) {
		t.Fatal("expected info severity to be enabled at info level")
	}
	if log.IsSeverityEnabled(log.Severity_Debug) {
		t.Fatal("expected debug severity to be disabled at info level")
	}
}

func TestIsSeverityEnabledWithGenericHandler(t *testing.T) {
	log.RegisterHandler(&testLogger{})
	t.Cleanup(func() {
		log.RegisterHandler(log.NewLogger(log.CreateStdoutLogWriter()))
	})

	if !log.IsSeverityEnabled(log.Severity_Debug) {
		t.Fatal("expected debug severity to be treated as enabled for generic handler")
	}
}
