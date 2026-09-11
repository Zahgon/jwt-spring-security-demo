// Package logging provides the named, hierarchically-levelled loggers the
// original gets from SLF4J over Logback, configured through the "logging.level"
// block of application.yml.
//
// Logger names are kept as the original's fully-qualified Java class names —
// "org.zerhusen.security.jwt.JWTFilter" and friends — because they are what
// "logging.level.org.zerhusen.security: DEBUG" selects on, and because keeping
// them makes the two implementations' output directly comparable.
package logging

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Level is a Logback log level.
type Level int

// Levels in ascending order of severity.
const (
	Trace Level = iota
	Debug
	Info
	Warn
	Error
	Off
)

var levelNames = map[Level]string{
	Trace: "TRACE", Debug: "DEBUG", Info: " INFO", Warn: " WARN", Error: "ERROR",
}

// ParseLevel converts a level name from application.yml. Unknown names fall
// back to Info, as Logback does for an unrecognised level.
func ParseLevel(name string) Level {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "TRACE":
		return Trace
	case "DEBUG":
		return Debug
	case "WARN":
		return Warn
	case "ERROR":
		return Error
	case "OFF":
		return Off
	default:
		return Info
	}
}

// Factory hands out loggers whose level comes from a set of name prefixes, the
// longest matching prefix winning — Logback's logger hierarchy.
type Factory struct {
	out    io.Writer
	root   Level
	levels []prefixLevel
	pid    int

	mu sync.Mutex
}

type prefixLevel struct {
	prefix string
	level  Level
}

// NewFactory builds a factory writing to out. root is the level for loggers no
// prefix matches; levels maps logger-name prefixes to their levels.
func NewFactory(out io.Writer, root Level, levels map[string]Level) *Factory {
	f := &Factory{out: out, root: root, pid: os.Getpid()}
	for prefix, level := range levels {
		f.levels = append(f.levels, prefixLevel{prefix: prefix, level: level})
	}
	sort.Slice(f.levels, func(i, j int) bool {
		return len(f.levels[i].prefix) > len(f.levels[j].prefix)
	})
	return f
}

// Logger returns the logger called name.
func (f *Factory) Logger(name string) *Logger {
	return &Logger{factory: f, name: name, level: f.levelFor(name)}
}

func (f *Factory) levelFor(name string) Level {
	for _, candidate := range f.levels {
		if name == candidate.prefix || strings.HasPrefix(name, candidate.prefix+".") {
			return candidate.level
		}
	}
	return f.root
}

func (f *Factory) write(level Level, name, message string) {
	line := fmt.Sprintf("%s %s %d --- %-40s : %s\n",
		time.Now().Format("2006-01-02 15:04:05.000"), levelNames[level], f.pid, name, message)

	f.mu.Lock()
	defer f.mu.Unlock()
	io.WriteString(f.out, line)
}

// Logger is a named logger. The Trace/Debug/Info methods take a format string
// in the style of fmt, standing in for SLF4J's "{}" placeholders.
type Logger struct {
	factory *Factory
	name    string
	level   Level
}

// Name returns the logger's name.
func (l *Logger) Name() string { return l.name }

// Enabled reports whether the logger would emit at level.
func (l *Logger) Enabled(level Level) bool { return level >= l.level }

// Trace logs at TRACE.
func (l *Logger) Trace(format string, args ...any) { l.log(Trace, format, args...) }

// Debug logs at DEBUG.
func (l *Logger) Debug(format string, args ...any) { l.log(Debug, format, args...) }

// Info logs at INFO.
func (l *Logger) Info(format string, args ...any) { l.log(Info, format, args...) }

// Warn logs at WARN.
func (l *Logger) Warn(format string, args ...any) { l.log(Warn, format, args...) }

// Error logs at ERROR.
func (l *Logger) Error(format string, args ...any) { l.log(Error, format, args...) }

func (l *Logger) log(level Level, format string, args ...any) {
	if !l.Enabled(level) {
		return
	}
	l.factory.write(level, l.name, fmt.Sprintf(format, args...))
}

// Discard is a factory that drops everything, for tests that do not assert on
// log output.
func Discard() *Factory { return NewFactory(io.Discard, Off, nil) }
