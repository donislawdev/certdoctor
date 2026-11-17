//go:build !darwin

package parts

// ToolkitNotch is the step the toolkit hands over for one notch of a wheel on
// Windows and Linux: GLFW reports a notch as 1 and the toolkit multiplies it
// by scrollSpeed, 25 in fyne v2.8.2 (internal/driver/glfw/scroll_speed_default.go).
// TestTheWheelStepIsTheToolkitsStep reads that file, so a toolkit that changes
// its step turns a guard red rather than every notch moving another distance.
const ToolkitNotch = 25

// wheelDistance is how far a wheel turned by dy moves an area: the notches dy
// stands for, each the window's distance. A touchpad's fraction of a notch
// stays a fraction.
func wheelDistance(dy float32) float32 {
	return dy / ToolkitNotch * notchDistance()
}
