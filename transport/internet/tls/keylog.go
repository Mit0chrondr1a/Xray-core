package tls

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

var masterKeyLogWriters struct {
	sync.Mutex
	writers map[string]*os.File
}

func MasterKeyLogWriter(path string) io.Writer {
	if path == "" || path == "none" {
		return nil
	}

	masterKeyLogWriters.Lock()
	defer masterKeyLogWriters.Unlock()

	if writer, found := masterKeyLogWriters.writers[path]; found {
		return writer
	}

	writer, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		errors.LogErrorInner(context.Background(), err, "failed to open ", path, " as master key log")
		return nil
	}
	info, err := writer.Stat()
	if err != nil {
		errors.LogWarningInner(context.Background(), err, "failed to stat ", path, " after opening as master key log")
	} else if info.Mode().Perm()&0o077 != 0 {
		if os.Getenv("XRAY_ALLOW_INSECURE_KEYLOG") != "1" {
			errors.LogWarning(context.Background(), "master key log ", path, " is more permissive than 0600, refusing to write (set XRAY_ALLOW_INSECURE_KEYLOG=1 to override)")
			writer.Close()
			return nil
		}
		errors.LogWarning(context.Background(), "master key log ", path, " is more permissive than 0600 (override via XRAY_ALLOW_INSECURE_KEYLOG=1)")
	}

	if masterKeyLogWriters.writers == nil {
		masterKeyLogWriters.writers = make(map[string]*os.File)
	}
	masterKeyLogWriters.writers[path] = writer
	return writer
}

// CloseMasterKeyLogWriters closes all cached key log file handles.
// Should be called during process shutdown.
func CloseMasterKeyLogWriters() {
	masterKeyLogWriters.Lock()
	defer masterKeyLogWriters.Unlock()
	for path, writer := range masterKeyLogWriters.writers {
		writer.Close()
		delete(masterKeyLogWriters.writers, path)
	}
}
