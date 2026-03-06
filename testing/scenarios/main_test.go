package scenarios

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	if shortModeEnabled() && os.Getenv("XRAY_SCENARIO_SHORT") != "1" {
		fmt.Println("skipping testing/scenarios in short mode; set XRAY_SCENARIO_SHORT=1 to run scenario tests")
		os.Exit(0)
	}

	genTestBinaryPath()
	defer testBinaryCleanFn()

	os.Exit(m.Run())
}

func shortModeEnabled() bool {
	for _, arg := range os.Args[1:] {
		switch {
		case arg == "-test.short", arg == "-short":
			return true
		case strings.HasPrefix(arg, "-test.short="):
			return arg != "-test.short=false"
		case strings.HasPrefix(arg, "-short="):
			return arg != "-short=false"
		}
	}

	return false
}
