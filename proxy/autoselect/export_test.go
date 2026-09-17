package autoselect

import "time"

// SetStalledAfter shortens the stall threshold for a test and returns the restore function.
func SetStalledAfter(d time.Duration) func() {
	old := stalledAfter
	stalledAfter = d
	return func() { stalledAfter = old }
}
