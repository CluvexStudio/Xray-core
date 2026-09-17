package singbox

// HoldStarts makes every sing-box instance wait for release before it starts. The returned func undoes it.
func HoldStarts(release <-chan struct{}) (undo func()) {
	hold := func() { <-release }
	beforeBoxStart.Store(&hold)
	return func() { beforeBoxStart.Store(nil) }
}
