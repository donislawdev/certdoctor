//go:build !windows

package file

// liveAppAlias refuses every path: app execution aliases are reparse points
// of Windows, and nothing elsewhere is one.
func liveAppAlias(string) (string, error) { return "", ErrNotAnAppAlias }
