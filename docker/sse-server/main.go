//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

/* Simple SSE server
 * Per-client event timing: each client gets events starting 1s after connection
 * Configurable via environment variables:
 * SSE_PORT - port to listen on (default 8080)
 * SSE_PATH - path to listen on (default /events)
 * SSE_INTERVAL - interval in seconds (default 1)
 * HEALTH_PATH - health check path (default /health)
 *
 * Endpoints:
 * - /health - health check
 * - /events - infinite stream, per-client timing
 * - /events/<n> - sends exactly <n> events, then closes
 * - /events/body/<n1>/<str1>/<n2>/<str2> - custom message sequence
 * - /events/bytes/<n>/<size> - sends <n> events of size <size>
 */

// writeSSEBaseHeaders writes common SSE headers except the Connection header,
// which is configured by each handler (keep-alive for infinite, close for finite).
func writeSSEBaseHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// sendEvent sends a single SSE event and flushes it. It returns false if the
// client context is done, true otherwise.
func sendEvent(ctx context.Context, w http.ResponseWriter, flusher http.Flusher, id, eventName, payload string) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}
	fmt.Fprintf(w, "id: %s\n", id)
	fmt.Fprintf(w, "event: %s\n", eventName)
	fmt.Fprintf(w, "data: %s\n\n", payload)
	flusher.Flush()
	return true
}

// sseStreamHandler handles /events (infinite) and /events/<n> (finite) streams.
// If maxEvents is nil, the connection is kept alive and events are sent forever.
func sseStreamHandler(interval int, maxEvents *int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeSSEBaseHeaders(w)
		if maxEvents == nil {
			w.Header().Set("Connection", "keep-alive")
		} else {
			w.Header().Set("Connection", "close")
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		sent := 0
		n := 1
		if maxEvents != nil {
			n = *maxEvents
		}

		for i := 0; maxEvents == nil || sent < n; i++ {
			time.Sleep(time.Duration(interval) * time.Second)
			message := fmt.Sprintf("Server time: %s", time.Now().Format(time.RFC3339))
			if !sendEvent(r.Context(), w, flusher, "001", "ServerTimeUpdate", message) {
				return
			}
			sent++
		}
	}
}

// countHandler parses /events/<n> and delegates to the finite sseStreamHandler.
func countHandler(basePath string, interval int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nStr := strings.TrimPrefix(r.URL.Path, basePath+"/")
		if nStr == "" {
			http.Error(w, "invalid path; expected /events/<n>", http.StatusBadRequest)
			return
		}
		n, err := strconv.Atoi(nStr)
		if err != nil || n < 0 {
			http.Error(w, "invalid events count", http.StatusBadRequest)
			return
		}
		h := sseStreamHandler(interval, &n)
		h(w, r)
	}
}

// bytesHandler handles /events/bytes/<n>/<size> streams.
func bytesHandler(basePath string, interval int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		nStr := strings.TrimPrefix(r.URL.Path, basePath+"/bytes/")
		if nStr == "" {
			http.Error(w, "invalid path; expected /events/bytes/<n>/<size>", http.StatusBadRequest)
			return
		}
		parts := strings.Split(nStr, "/")
		if len(parts) != 2 {
			http.Error(w, "invalid path; expected /events/bytes/<n>/<size>", http.StatusBadRequest)
			return
		}
		n, err := strconv.Atoi(parts[0])
		if err != nil || n < 0 {
			http.Error(w, "invalid events count", http.StatusBadRequest)
			return
		}
		size, err := strconv.Atoi(parts[1])
		if err != nil || size <= 0 {
			http.Error(w, "invalid size", http.StatusBadRequest)
			return
		}

		writeSSEBaseHeaders(w)
		w.Header().Set("Connection", "close")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		message := strings.Repeat(".", size)
		for i := 0; i < n; i++ {
			time.Sleep(time.Duration(interval) * time.Second)
			if !sendEvent(r.Context(), w, flusher, "002", "CustomEventSize", message) {
				return
			}
		}
	}
}

// bodyHandler handles /events/body/<n1>/<str1>/<n2>/<str2> sequences.
func bodyHandler(basePath string, interval int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		trimmed := strings.TrimPrefix(r.URL.Path, basePath+"/body/")
		parts := strings.Split(trimmed, "/")
		if len(parts) != 4 {
			http.Error(w, "invalid path; expected /events/body/<n1>/<str1>/<n2>/<str2>", http.StatusBadRequest)
			return
		}

		n1, err1 := strconv.Atoi(parts[0])
		n2, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil || n1 < 0 || n2 < 0 {
			http.Error(w, "invalid counts", http.StatusBadRequest)
			return
		}

		str1, err := url.PathUnescape(parts[1])
		if err != nil {
			http.Error(w, "invalid string1", http.StatusBadRequest)
			return
		}
		str2, err := url.PathUnescape(parts[3])
		if err != nil {
			http.Error(w, "invalid string2", http.StatusBadRequest)
			return
		}

		writeSSEBaseHeaders(w)
		w.Header().Set("Connection", "close")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		for i := 0; i < n1; i++ {
			time.Sleep(time.Duration(interval) * time.Second)
			if !sendEvent(r.Context(), w, flusher, "003", "CustomEvent", str1) {
				return
			}
		}
		for i := 0; i < n2; i++ {
			time.Sleep(time.Duration(interval) * time.Second)
			if !sendEvent(r.Context(), w, flusher, "003", "CustomEvent", str2) {
				return
			}
		}
	}
}

// healthHandler returns a simple health check handler.
func healthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}

func main() {
	// Configuration
	port := os.Getenv("SSE_PORT")
	if port == "" {
		port = "8080"
	}
	path := os.Getenv("SSE_PATH")
	if path == "" {
		path = "/events"
	}
	healthPath := os.Getenv("HEALTH_PATH")
	if healthPath == "" {
		healthPath = "/health"
	}
	intervalStr := os.Getenv("SSE_INTERVAL")
	if intervalStr == "" {
		intervalStr = "1"
	}
	interval, err := strconv.Atoi(intervalStr)
	if err != nil || interval <= 0 {
		interval = 1
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Routes
	http.HandleFunc(path, sseStreamHandler(interval, nil))        // infinite
	http.HandleFunc(path+"/", countHandler(path, interval))       // finite count
	http.HandleFunc(path+"/bytes/", bytesHandler(path, interval)) // bytes
	http.HandleFunc(path+"/body/", bodyHandler(path, interval))   // body
	http.HandleFunc(healthPath, healthHandler())                  // health

	// Start server
	addr := ":" + port
	logger.Info("SSE server starting", "addr", addr, "path", path, "health", healthPath)
	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Error("HTTP server error", "error", err)
	}
}
