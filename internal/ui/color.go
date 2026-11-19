// Package ui provides minimal ANSI color helpers for CLI output.
package ui

import "os"

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Bold   = "\033[1m"
)

// enabled respects the NO_COLOR convention (https://no-color.org/) - set
// NO_COLOR to any non-empty value to disable colored output.
func enabled() bool {
	return os.Getenv("NO_COLOR") == ""
}

func Colorize(s, color string) string {
	if !enabled() {
		return s
	}
	return color + s + Reset
}

func Success(s string) string { return Colorize(s, Green) }
func Fail(s string) string    { return Colorize(s, Red) }
func Warn(s string) string    { return Colorize(s, Yellow) }
