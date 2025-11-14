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

	sse "github.com/rifaideen/sse-server"
)

/* Simple SSE server
 * based on the example: https://github.com/rifaideen/sse-server?tab=readme-ov-file#usage
 * It doesn't wait for any client to connect, it just starts broadcasting to all the connected clients.
 * can be configured via environment variables:
 * SSE_PORT - port to listen on (default 8080)
 * SSE_PATH - path to listen on (default /events)
 * SSE_INTERVAL - interval in seconds to send server time updates (default 1)
 * HEALTH_PATH - path to health check endpoint (default /health)
 *
 * endpoints:
 *	- /health - simple health check endpoint
 *	- /events - continuously streams events
 *	- /events/<n> - sends <n> events and then closes the connection
 *  - /events/body/<n1>/<string1>/<n2>/<string2> send <n1> events with body <string1> and <n2> events with body <string2>
 */

func main() {
	// Configure via environment variables only
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
	server, errNew := sse.New(logger)
	if errNew != nil {
		logger.Error("failed to create sse server", "error", errNew)
		return
	}

	go server.Listen()
	defer server.Close()

	// Shared SSE handler
	// maxEvents == nil  -> unlimited stream
	// maxEvents != nil  -> send exactly *maxEvents events and then return
	sseHandler := func(maxEvents *int, keepAlive bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			if keepAlive {
				w.Header().Set("Connection", "keep-alive")
			} else {
				w.Header().Set("Connection", "close")
			}

			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
				return
			}

			// create buffered channel to receive notifications and add it to the server
			chNotification := make(chan string, 10)
			server.Add <- chNotification
			defer func() {
				server.Remove <- chNotification
				close(chNotification)
			}()

			sent := 0
			for {
				// If we have a limit and we've reached it, stop.
				if maxEvents != nil && sent >= *maxEvents {
					return
				}

				select {
				case message := <-chNotification:
					if message == sse.QUIT {
						return
					}
					fmt.Fprintf(w, "event: ServerTimeUpdate\n")
					fmt.Fprintf(w, "data: %s\n\n", message)
					flusher.Flush()
					if maxEvents != nil {
						sent++
					}
				case <-r.Context().Done():
					return
				}
			}
		}
	}

	// Infinite event stream on /events
	http.HandleFunc(path, sseHandler(nil, true))

	// Endpoint to stream exactly N events and then close the HTTP connection
	// default: /events/<n>
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

		// Reuse the shared handler with a concrete N and "Connection: close"
		handler := sseHandler(&n, false)
		handler(w, r)
	})

	// Endpoint to stream exactly N1 events with custom body string1, then
	// N2 events with custom body string2 and finally close.
	// default: /events/body/<n1>/<string1>/<n2>/<string2>
	http.HandleFunc(path+"/body/", func(w http.ResponseWriter, r *http.Request) {
		trimmed := strings.TrimPrefix(r.URL.Path, path+"/body/")
		parts := strings.Split(trimmed, "/")
		if len(parts) != 4 {
			http.Error(w, "invalid body endpoint path; expected /events/body/<n1>/<string1>/<n2>/<string2>", http.StatusBadRequest)
			return
		}

		n1, err1 := strconv.Atoi(parts[0])
		n2, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil || n1 < 0 || n2 < 0 {
			http.Error(w, "invalid counts in path", http.StatusBadRequest)
			return
		}

		str1, err := url.PathUnescape(parts[1])
		if err != nil {
			http.Error(w, "invalid string1 encoding", http.StatusBadRequest)
			return
		}
		str2, err := url.PathUnescape(parts[3])
		if err != nil {
			http.Error(w, "invalid string2 encoding", http.StatusBadRequest)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "close")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
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

	// Simple health check endpoint (configurable path)
	// default: /health
	http.HandleFunc(healthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok responsebodycode"))
	})

	// Send server time updates
	go func() {
		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			server.Notification <- fmt.Sprintf("Server time: %s", time.Now().Format(time.RFC3339))
		}
	}()

	addr := ":" + port
	fmt.Printf("SSE server listening on %s with events path %s, health path %s\n", addr, path, healthPath)

	if err := http.ListenAndServe(addr, nil); err != nil {
		logger.Error("HTTP server error", "error", err)
	}
}
