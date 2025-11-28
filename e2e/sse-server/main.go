//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
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
 */

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

	// Shared handler for /events and /events/<n>
	// maxEvents == nil -> infinite, otherwise send N and close
	sseHandler := func(maxEvents *int) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			// Close connection after N events, otherwise keep alive
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
				// Check if the client disconnected
				select {
				case <-r.Context().Done():
					return
				default:
				}

				// Send event
				message := fmt.Sprintf("Server time: %s", time.Now().Format(time.RFC3339))
				fmt.Fprintf(w, "event: ServerTimeUpdate\n")
				fmt.Fprintf(w, "data: %s\n\n", message)
				flusher.Flush()
				sent++
			}
		}
	}

	// Infinite stream
	http.HandleFunc(path, sseHandler(nil))

	// Send N events and close
	http.HandleFunc(path+"/", func(w http.ResponseWriter, r *http.Request) {
		nStr := strings.TrimPrefix(r.URL.Path, path+"/")
		if nStr == "" {
			http.NotFound(w, r)
			return
		}
		n, err := strconv.Atoi(nStr)
		if err != nil || n < 0 {
			http.Error(w, "invalid events count", http.StatusBadRequest)
			return
		}
		handler := sseHandler(&n)
		handler(w, r)
	})

	// Custom body sequence
	http.HandleFunc(path+"/body/", func(w http.ResponseWriter, r *http.Request) {
		trimmed := strings.TrimPrefix(r.URL.Path, path+"/body/")
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

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "close")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		sendEvent := func(payload string) bool {
			select {
			case <-r.Context().Done():
				return false
			default:
			}
			fmt.Fprintf(w, "event: CustomEvent\n")
			fmt.Fprintf(w, "data: %s\n\n", payload)
			flusher.Flush()
			return true
		}

		for i := 0; i < n1; i++ {
			time.Sleep(time.Duration(interval) * time.Second)
			if !sendEvent(str1) {
				return
			}
		}
		for i := 0; i < n2; i++ {
			time.Sleep(time.Duration(interval) * time.Second)
			if !sendEvent(str2) {
				return
			}
		}
	})

	// Health check
	http.HandleFunc(healthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	// Start server
	addr := ":" + port
	logger.Info("SSE server starting", "addr", addr, "path", path, "health", healthPath)
	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Error("HTTP server error", "error", err)
	}
}
