//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	sse "github.com/rifaideen/sse-server"
)

// Simple SSE server that sends periodic notifications
// It doesn't wait for any client to connect, it just starts broadcasting to all the connected clients
// port, paths and interval can be configured via environment variables
// based on the example: https://github.com/rifaideen/sse-server?tab=readme-ov-file#usage
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
		healthPath = "/healthz"
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
				fmt.Fprintf(w, "data: %s\n\n", message)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})

	// Simple healthcheck endpoint (configurable path)
	http.HandleFunc(healthPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
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
