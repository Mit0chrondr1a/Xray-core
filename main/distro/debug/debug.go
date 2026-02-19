package debug

import (
	"net/http"
)

func init() {
	go func() {
		http.ListenAndServe("127.0.0.1:6060", nil)
	}()
}
