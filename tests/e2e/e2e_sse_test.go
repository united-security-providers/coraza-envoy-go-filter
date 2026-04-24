//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type SSEResult struct {
	EventNumber int
	Data        string
	Elapsed     time.Duration
}

func readSSEEvents(host string, url string, expectedCount int, timeout time.Duration, additionalHeaders ...string) ([]SSEResult, error) {
	start := time.Now()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(additionalHeaders); i += 2 {
		req.Header.Set(additionalHeaders[i], additionalHeaders[i+1])
	}
	req.Host = host
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	//start := time.Now()
	scanner := bufio.NewScanner(resp.Body)
	var results []SSEResult

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		elapsed := time.Since(start)
		results = append(results, SSEResult{
			EventNumber: len(results) + 1,
			Data:        strings.TrimPrefix(line, "data: "),
			Elapsed:     elapsed,
		})
		if len(results) >= expectedCount {
			break
		}
	}
	return results, scanner.Err()
}

func verifySSETiming(results []SSEResult, tolerance time.Duration) error {
	for _, r := range results {
		expected := time.Duration(r.EventNumber) * time.Second
		diff := r.Elapsed - expected
		if diff < 0 {
			diff = -diff
		}
		if diff > tolerance {
			return fmt.Errorf("event %d arrived at %v, expected %v +/- %v", r.EventNumber, r.Elapsed, expected, tolerance)
		}
	}
	return nil
}

func TestE2ESSESecRuleEngineOff(t *testing.T) {
	results, err := readSSEEvents("no-waf.example.com", envoyEndpoint+"/events", 4, 15*time.Second)
	require.NoError(t, err)
	require.Equal(t, 4, len(results))

	err = verifySSETiming(results, 200*time.Millisecond)
	require.NoError(t, err)

	for _, r := range results {
		require.True(t, strings.HasPrefix(r.Data, "Server time:"), "expected SSE data to start with 'Server time:'")
	}
}

func TestE2ESSEExactEvents(t *testing.T) {
	results, err := readSSEEvents("no-waf.example.com", envoyEndpoint+"/events/5", 5, 10*time.Second)
	require.NoError(t, err)
	require.Equal(t, 5, len(results))

	err = verifySSETiming(results, 200*time.Millisecond)
	require.NoError(t, err)
}

func TestE2ESSESecResponseBodyAccessOff(t *testing.T) {
	results, err := readSSEEvents("body-off.example.com", envoyEndpoint+"/events", 4, 15*time.Second)
	require.NoError(t, err)
	require.Equal(t, 4, len(results))

	err = verifySSETiming(results, 200*time.Millisecond)
	require.NoError(t, err)
}

func TestE2ESSEExactSecResponseBodyAccessOff(t *testing.T) {
	results, err := readSSEEvents("body-off.example.com", envoyEndpoint+"/events/5", 5, 10*time.Second)
	require.NoError(t, err)
	require.Equal(t, 5, len(results))

	err = verifySSETiming(results, 200*time.Millisecond)
	require.NoError(t, err)
}

func TestE2ESSEPERuleDisableResponseBodyInspection(t *testing.T) {
	results, err := readSSEEvents("sse.example.com", envoyEndpoint+"/events", 4, 15*time.Second)
	require.NoError(t, err)
	require.Equal(t, 4, len(results))

	err = verifySSETiming(results, 200*time.Millisecond)
	require.NoError(t, err)

	for _, r := range results {
		require.True(t, strings.HasPrefix(r.Data, "Server time:"), "expected SSE data to start with 'Server time:'")
	}
}
