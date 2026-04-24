//  Copyright © 2026 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

type LogCollector struct {
	mu      sync.Mutex
	lines   []string
	maxSize int
}

func NewLogCollector(maxSize int) *LogCollector {
	if maxSize <= 0 {
		maxSize = 5000
	}
	return &LogCollector{maxSize: maxSize}
}

func (c *LogCollector) Accept(l testcontainers.Log) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, string(l.Content))
	if len(c.lines) > c.maxSize {
		c.lines = c.lines[len(c.lines)-c.maxSize:]
	}
}

func (c *LogCollector) Snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.lines))
	copy(out, c.lines)
	return out
}

func (c *LogCollector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = nil
}

func (c *LogCollector) CountMatches(re *regexp.Regexp) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	count := 0
	for _, ln := range c.lines {
		if re.MatchString(ln) {
			count++
		}
	}
	return count
}

func (c *LogCollector) WaitFor(re *regexp.Regexp, timeout, pollEvery time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return false
		}
		if c.CountMatches(re) > 0 {
			return true
		}
		time.Sleep(pollEvery)
	}
}

type StdoutLogConsumer struct {
	Prefix string
}

func (lc *StdoutLogConsumer) Accept(l testcontainers.Log) {
	fmt.Printf("[%s] %s", lc.Prefix, string(l.Content))
}
