//go:build windows

package probe

import "os/exec"

// isolate leaves the child as exec starts it. Ending a wrapper's own children
// on Windows needs a job object, which needs unsafe - OBS197, a question for
// the owner with a measurement behind it rather than a guess.
func isolate(*exec.Cmd) {}
