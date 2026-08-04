package planted

// Planted violations: a path from somebody else's configuration turned into
// something readable, and the same path merely ASKED ABOUT.
//
// Both shapes are here because both leave this machine. The 21 seconds measured
// in the review this rule comes from were spent on an existence check, not on a
// read - so a scanner that only knew about opening would report a clean tree
// while the slowest, most revealing call went past it.
import "os"

func read(path string) ([]byte, error) { return os.ReadFile(path) }

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
