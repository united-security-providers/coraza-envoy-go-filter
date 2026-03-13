// Copyright © 2026 United Security Providers AG, Switzerland
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"log/slog"

	api "github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

type LogFormat string

const (
	FormatText LogFormat = "text"
	FormatJson LogFormat = "json"
	FormatFtw  LogFormat = "ftw"
)

func (f LogFormat) String() string {
	return string(f)
}

var logger Logger

type Logger interface {
	Error(msg string, args ...any)
	Warn(msg string, args ...any)
	Info(msg string, args ...any)
	Debug(msg string, args ...any)
	With(args ...any) Logger
	WithGroup(name string) Logger
}

type envoyLogger struct {
	l *slog.Logger
}

func (a *envoyLogger) Error(msg string, args ...any) { a.l.Error(msg, args...) }
func (a *envoyLogger) Warn(msg string, args ...any)  { a.l.Warn(msg, args...) }
func (a *envoyLogger) Info(msg string, args ...any)  { a.l.Info(msg, args...) }
func (a *envoyLogger) Debug(msg string, args ...any) { a.l.Debug(msg, args...) }
func (a *envoyLogger) With(args ...any) Logger       { return &envoyLogger{l: a.l.With(args...)} }
func (a *envoyLogger) WithGroup(name string) Logger  { return &envoyLogger{l: a.l.WithGroup(name)} }

func Init(format LogFormat) {
	opts := &slog.HandlerOptions{
		Level: logLevel(),
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey || a.Key == slog.LevelKey {
				return slog.Attr{}
			}
			return a
		},
	}
	logger = &envoyLogger{l: slog.New(&envoyHandler{
		opts: opts,
		json: format == FormatJson,
	})}
}

func logLevel() slog.Level {
	switch api.GetLogLevel() {
	case api.Trace, api.Debug:
		return slog.LevelDebug
	case api.Info:
		return slog.LevelInfo
	case api.Warn:
		return slog.LevelWarn
	case api.Error:
		return slog.LevelError
	}
	return slog.LevelDebug
}

func GetLogger() Logger {
	return logger
}
