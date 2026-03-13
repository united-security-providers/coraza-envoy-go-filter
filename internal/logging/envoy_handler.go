// Copyright © 2026 United Security Providers AG, Switzerland
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"context"
	"log/slog"
	"strings"

	api "github.com/envoyproxy/envoy/contrib/golang/common/go/api"
)

type groupOrAttr struct {
	attrs []slog.Attr
	group string
}

type envoyHandler struct {
	opts        *slog.HandlerOptions
	json        bool
	groupOrAttr []groupOrAttr
}

func (h *envoyHandler) Enabled(_ context.Context, level slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return level >= minLevel
}

// Handle formats the record using a one-shot slog.TextHandler or
// slog.JSONHandler writing into a local buffer, then dispatches the result
// to the correct Envoy C ABI log function. Each call is fully independent.
func (h *envoyHandler) Handle(ctx context.Context, r slog.Record) error {
	builder := strings.Builder{}

	var inner slog.Handler
	if h.json {
		inner = slog.NewJSONHandler(&builder, h.opts)
	} else {
		inner = slog.NewTextHandler(&builder, h.opts)
	}

	for _, o := range h.groupOrAttr {
		if o.group != "" {
			inner = inner.WithGroup(o.group)
		} else {
			inner = inner.WithAttrs(o.attrs)
		}
	}

	if err := inner.Handle(ctx, r); err != nil {
		return err
	}

	line := builder.String()[:builder.Len()-1]
	switch r.Level {
	case slog.LevelError:
		api.LogError(line)
	case slog.LevelWarn:
		api.LogWarn(line)
	case slog.LevelInfo:
		api.LogInfo(line)
	case slog.LevelDebug:
		api.LogDebug(line)
	}
	return nil
}

func (h *envoyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttributes := make([]groupOrAttr, len(h.groupOrAttr)+1)
	copy(newAttributes, h.groupOrAttr)
	newAttributes[len(h.groupOrAttr)] = groupOrAttr{attrs: attrs}
	return &envoyHandler{opts: h.opts, json: h.json, groupOrAttr: newAttributes}
}

func (h *envoyHandler) WithGroup(name string) slog.Handler {
	newGroup := make([]groupOrAttr, len(h.groupOrAttr)+1)
	copy(newGroup, h.groupOrAttr)
	newGroup[len(h.groupOrAttr)] = groupOrAttr{group: name}
	return &envoyHandler{opts: h.opts, json: h.json, groupOrAttr: newGroup}
}
