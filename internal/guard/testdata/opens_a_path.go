package planted

// Planted violations: a path from somebody else's configuration turned into
// something readable, the same path merely ASKED ABOUT, and the same path
// FOLLOWED to wherever it really leads.
//
// All three shapes are here because all three leave this machine. The 21
// seconds measured in the review this rule comes from were spent on an
// existence check, not on a read - so a scanner that only knew about opening
// would report a clean tree while the slowest, most revealing call went past
// it. The third shape was added on 2026-08-05: resolving a link walks every
// component of the path on disk, and for a while this scanner asked only
// whether the package was os, so it never saw that one at all.
import (
	"os"
	"path/filepath"
)

func read(path string) ([]byte, error) { return os.ReadFile(path) }

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func follow(path string) (string, error) { return filepath.EvalSymlinks(path) }
