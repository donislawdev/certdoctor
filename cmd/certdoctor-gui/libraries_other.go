//go:build !windows

package main

// searchSystemOnly sets nothing outside Windows. The search order it narrows,
// with the program's own directory first, is the Windows loader's (OBS214,
// ADR152).
func searchSystemOnly() error { return nil }
