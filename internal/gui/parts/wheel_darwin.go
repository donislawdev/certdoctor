//go:build darwin

package parts

// wheelDistance leaves the wheel as the toolkit hands it over on macOS. There
// the system's deltas arrive scaled and accelerated, as every other program
// gets them, and the toolkit multiplies them by its scrollSpeed of 10 (fyne
// v2.8.2, internal/driver/glfw/scroll_speed_darwin.go) - a Mac already
// scrolls this window as it scrolls anything else.
func wheelDistance(dy float32) float32 { return dy }
