// Fixture, never compiled. Production code reaching for the filesystem.
package store

import "os"

func install(anchor []byte) error {
	return os.WriteFile("trust-store.pem", anchor, 0o644)
}
