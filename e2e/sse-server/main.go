//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log/slog"
	"net/http"
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

	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		// create buffered channel to receive notifications and add it to the server
		chNotification := make(chan string, 10)
		server.Add <- chNotification

		defer func() {
			// remove the channel from the server and close the channel
			server.Remove <- chNotification
			close(chNotification)
		}()

		for {
			select {
			case message := <-chNotification:
				// Quit signal received, exit the loop
				if message == sse.QUIT {
					return
				}

				// send message to client
				fmt.Fprintf(w, "event: ServerTimeUpdate\n")
				fmt.Fprintf(w, "data: %s\n\n", message)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})

	// Endpoint to stream exactly N events and then close the HTTP connection
	// /events/<n>
	http.HandleFunc(path+"/", func(w http.ResponseWriter, r *http.Request) {
		// Only handle paths with a numeric suffix
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

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		// Inform the client we will close after sending N events
		w.Header().Set("Connection", "close")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		chNotification := make(chan string, 10)
		server.Add <- chNotification
		defer func() {
			server.Remove <- chNotification
			close(chNotification)
		}()

		sent := 0
		for sent < n {
			select {
			case message := <-chNotification:
				if message == sse.QUIT {
					return
				}
				fmt.Fprintf(w, "event: ServerTimeUpdate\n")
				fmt.Fprintf(w, "data: %s\n\n", message)
				flusher.Flush()
				sent++
			case <-r.Context().Done():
				return
			}
		}
		// Return to end the response; client connection will close
		return
	})

	// Simple health check endpoint (configurable path)
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
