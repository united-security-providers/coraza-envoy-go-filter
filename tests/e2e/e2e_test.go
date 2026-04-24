//  Copyright © 2023 Axkea, spacewander
//  Copyright © 2025 United Security Providers AG, Switzerland
//  SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

var (
	envoyEndpoint string
	backendLogs   *LogCollector
)

func absPath(components ...string) (string, error) {
	path, err := filepath.Abs(filepath.Join(components...))
	if err != nil {
		return "", fmt.Errorf("could not get absolute path of %s: %w", components, err)
	}
	return path, nil
}

func setupEnvironment(enableLogs bool) (string, func(), error) {
	ctx := context.Background()

	soPath, err := absPath("..", "..", "build", "coraza-waf.so")
	if err != nil {
		return "", nil, fmt.Errorf("get .so path: %w", err)
	}
	if _, err := os.Stat(soPath); err != nil {
		return "", nil, fmt.Errorf("build/coraza-waf.so not found. Run `make build` first")
	}

	net, err := network.New(ctx)
	if err != nil {
		return "", nil, fmt.Errorf("create network: %w", err)
	}

	httpbinLogs := NewLogCollector(5000)

	var httpbinConsumers []testcontainers.LogConsumer
	var sseConsumers []testcontainers.LogConsumer
	var envoyConsumers []testcontainers.LogConsumer
	if enableLogs {
		httpbinConsumers = []testcontainers.LogConsumer{httpbinLogs, &StdoutLogConsumer{Prefix: "HTTPBIN"}}
		sseConsumers = []testcontainers.LogConsumer{&StdoutLogConsumer{Prefix: "SSE_SERVER"}}
		envoyConsumers = []testcontainers.LogConsumer{&StdoutLogConsumer{Prefix: "ENVOY"}}
	} else {
		httpbinConsumers = []testcontainers.LogConsumer{httpbinLogs}
		sseConsumers = []testcontainers.LogConsumer{}
		envoyConsumers = []testcontainers.LogConsumer{}
	}

	httpbin, err := testcontainers.Run(ctx,
		"mccutchen/go-httpbin:2.22.1",
		network.WithNetwork([]string{"httpbin"}, net),
		testcontainers.WithWaitStrategy(
			wait.ForLog("go-httpbin listening on http://0.0.0.0:8080"),
		),
		testcontainers.WithLogConsumerConfig(&testcontainers.LogConsumerConfig{
			Opts:      []testcontainers.LogProductionOption{testcontainers.WithLogProductionTimeout(10 * time.Second)},
			Consumers: httpbinConsumers,
		}),
	)
	if err != nil {
		net.Remove(ctx)
		return "", nil, fmt.Errorf("start httpbin: %w", err)
	}

	sseServer, err := testcontainers.Run(ctx,
		"e2e-sse-server",
		network.WithNetwork([]string{"sse-server"}, net),
		testcontainers.WithWaitStrategy(
			wait.ForHTTP("/health"),
		),
		testcontainers.WithLogConsumerConfig(&testcontainers.LogConsumerConfig{
			Opts:      []testcontainers.LogProductionOption{testcontainers.WithLogProductionTimeout(10 * time.Second)},
			Consumers: sseConsumers,
		}),
	)
	if err != nil {
		httpbin.Terminate(ctx)
		net.Remove(ctx)
		return "", nil, fmt.Errorf("build sse-server: %w", err)
	}

	envPath, err := absPath(".", "envoy.yaml")
	if err != nil {
		httpbin.Terminate(ctx)
		sseServer.Terminate(ctx)
		net.Remove(ctx)
		return "", nil, fmt.Errorf("get envoy.yaml path: %w", err)
	}

	customSetupPath, err := absPath(".", "custom_setup.conf")
	if err != nil {
		httpbin.Terminate(ctx)
		sseServer.Terminate(ctx)
		net.Remove(ctx)
		return "", nil, fmt.Errorf("get custom_setup.conf path: %w", err)
	}

	customRulesPath, err := absPath(".", "custom_rules")
	if err != nil {
		httpbin.Terminate(ctx)
		sseServer.Terminate(ctx)
		net.Remove(ctx)
		return "", nil, fmt.Errorf("get custom_rules path: %w", err)
	}

	envoy, err := testcontainers.Run(ctx,
		"coraza-waf-envoy",
		testcontainers.WithCmd(
			"-l debug", "-c /etc/envoy/envoy.yaml",
		),
		testcontainers.WithEnv(map[string]string{"GODEBUG": "cgocheck=0"}),
		testcontainers.WithFiles(
			testcontainers.ContainerFile{
				HostFilePath:      soPath,
				ContainerFilePath: "/etc/envoy/coraza-waf.so",
				FileMode:          0o755,
			},
			testcontainers.ContainerFile{
				HostFilePath:      envPath,
				ContainerFilePath: "/etc/envoy/envoy.yaml",
				FileMode:          0o444,
			},
			testcontainers.ContainerFile{
				HostFilePath:      customSetupPath,
				ContainerFilePath: "/etc/envoy/custom_setup.conf",
				FileMode:          0o444,
			},
			testcontainers.ContainerFile{
				HostFilePath:      customRulesPath,
				ContainerFilePath: "/etc/envoy/custom_rules",
				FileMode:          0o755,
			},
		),
		testcontainers.WithExposedPorts("8081/tcp"),
		network.WithNetwork([]string{"envoy"}, net),
		testcontainers.WithWaitStrategy(
			wait.ForListeningPort("8081/tcp"),
			wait.ForLog("all dependencies initialized. starting workers"),
			//wait.ForHTTP("/ready").WithPort("9999"),
		),
		testcontainers.WithLogConsumerConfig(&testcontainers.LogConsumerConfig{
			Opts:      []testcontainers.LogProductionOption{testcontainers.WithLogProductionTimeout(10 * time.Second)},
			Consumers: envoyConsumers,
		}),
	)
	if err != nil {
		httpbin.Terminate(ctx)
		sseServer.Terminate(ctx)
		net.Remove(ctx)
		return "", nil, fmt.Errorf("start envoy: %w", err)
	}

	endpoint, err := envoy.PortEndpoint(ctx, "8081", "http")
	if err != nil {
		httpbin.Terminate(ctx)
		sseServer.Terminate(ctx)
		envoy.Terminate(ctx)
		net.Remove(ctx)
		return "", nil, fmt.Errorf("get envoy endpoint: %w", err)
	}

	cleanup := func() {
		httpbin.Terminate(ctx)
		sseServer.Terminate(ctx)
		envoy.Terminate(ctx)
		net.Remove(ctx)
	}

	backendLogs = httpbinLogs

	fmt.Printf("returning endpoint: %v\n", endpoint)
	return endpoint, cleanup, nil
}

func TestMain(m *testing.M) {
	containerLogs := false
	parsedArgs := os.Args[1:]
	for argIdx, arg := range parsedArgs {
		if arg == "--" && argIdx+1 < len(parsedArgs) {
			if parsedArgs[argIdx+1] == "container-logs" {
				containerLogs = true
				continue
			}
		}
	}

	endpoint, cleanup, err := setupEnvironment(containerLogs)
	if err != nil {
		fmt.Printf("Failed to setup test environment: %v\n", err)
		os.Exit(1)
	}
	envoyEndpoint = endpoint

	defer func() {
		if r := recover(); r != nil {
			cleanup()
			panic(r)
		}
	}()

	code := m.Run()
	cleanup()
	os.Exit(code)
}

func checkRequest(t *testing.T, host string, url string, method string, expectedStatus int, expectEmptyBody *bool, data string, additionalHeaders ...string) (int, string) {
	client := http.Client{}
	var req *http.Request
	var err error

	if method == "POST" {
		req, err = http.NewRequest(method, url, strings.NewReader(data))
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	require.NoError(t, err)

	req.Host = host
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	for i := 0; i < len(additionalHeaders); i += 2 {
		req.Header.Set(additionalHeaders[i], additionalHeaders[i+1])
	}

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, expectedStatus, resp.StatusCode)

	if expectEmptyBody != nil {
		if *expectEmptyBody {
			require.Empty(t, string(body))
		} else {
			require.NotEmpty(t, string(body))
		}
	}

	return resp.StatusCode, string(body)
}

func checkInLogs(t *testing.T, status int, method string, url string) {
	// Assert: wait until we see the request in backend logs
	re := regexp.MustCompile(".*status=" + strconv.Itoa(status) + ".*method=" + strings.ToUpper(method) + ".*uri=.?" + url + ".*")
	ok := backendLogs.WaitFor(re, 3*time.Second, 100*time.Millisecond)
	require.True(t, ok, "expected %v request '%v' to reach backend;  \n logs: %v \n regex: %v", method, url, backendLogs.Snapshot(), re.String())
}

func checkNotInLogs(t *testing.T, method string, url string) {
	// Assert: verifiy there is NO request in backend logs
	re := regexp.MustCompile("method=" + strings.ToUpper(method) + ".*uri=.?" + url + ".*")
	time.Sleep(100 * time.Millisecond)
	matches := backendLogs.CountMatches(re)
	require.Equal(t, 0, matches, "did NOT expect %v request '%v' to reach backend;  \n logs: %v \n regex: %v", method, url, backendLogs.Snapshot(), re.String())
}

func TestE2EBasicReachability(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/anything?test=backend-available", http.MethodGet, http.StatusOK, &empty, "")
	checkInLogs(t, 200, http.MethodGet, "/anything\\?test=backend-available")
}

// Testing request/response phases
func TestE2ETrueNegativeRequestHeaderPhase(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/anything?arg=arg_1", "GET", http.StatusOK, &empty, "")
	checkInLogs(t, 200, http.MethodGet, "/anything\\?arg=arg_1")
}

func TestE2ETruePositiveRequestHeaderPhase(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/admin", "GET", http.StatusForbidden, &empty, "")
	checkNotInLogs(t, http.MethodGet, "/admin")
}

func TestE2ETrueNegativeRequestBodyPhase(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/post", "POST", http.StatusOK, &empty, "This is a valid payload")
	checkInLogs(t, 200, http.MethodPost, "/post")
}

func TestE2ETruePositiveRequestBodyPhase(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/post", "POST", http.StatusForbidden, &empty, "maliciouspayload")
	checkNotInLogs(t, http.MethodPost, "/post")
}

func TestE2ETruePositiveRequestBodyInsideLimitProcessPartial(t *testing.T) {
	data := fmt.Sprintf("prefix is 20 bytes %s suffix is 20 bytes", "maliciouspayload")
	empty := true
	backendLogs.Reset()
	checkRequest(t, "bar.example.com", envoyEndpoint+"/post", "POST", http.StatusForbidden, &empty, data)
	checkNotInLogs(t, http.MethodPost, "/post")
}

func TestE2ETruePositiveRequestBodyOutsideLimitProcessPartial(t *testing.T) {
	data := fmt.Sprintf("this very long prefix is just a little more than 40 bytes %s suffix is 20 bytes", "maliciouspayload")
	empty := false
	backendLogs.Reset()
	checkRequest(t, "bar.example.com", envoyEndpoint+"/post", "POST", http.StatusOK, &empty, data)
	checkInLogs(t, 200, http.MethodPost, "/post")
}

func TestE2ERequestBodyLimitReject(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "baz.example.com", envoyEndpoint+"/post", "POST", http.StatusRequestEntityTooLarge, &empty, "this payload is just a little more than 40 bytes")
	checkNotInLogs(t, http.MethodPost, "/post")
}

func TestE2ETruePositiveResponseHeaderPhase(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/status/406", "GET", http.StatusForbidden, &empty, "")
	//httpbin sends the status code so we expect the request in the logs
	checkInLogs(t, 406, http.MethodGet, "/status/406")
}

func TestE2ETrueNegativeResponseBodyPhase(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/post", "POST", http.StatusOK, &empty, "This is a valid payload")
	checkInLogs(t, 200, http.MethodPost, "/post")
}

func TestE2ETruePositiveResponseBodyPhase(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/post", "POST", http.StatusForbidden, &empty, "responsebodycode")
	checkInLogs(t, 200, http.MethodPost, "/post")
}

func TestE2ETruePositiveResponseBodyInsideLimitProcessPartial(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "bar.example.com", envoyEndpoint+"/post", "POST", http.StatusForbidden, &empty, "responsebodycode")
	checkInLogs(t, 200, http.MethodPost, "/post")
}

func TestE2ETruePositiveResponseBodyOutsideLimitProcessPartial(t *testing.T) {
	data := fmt.Sprintf("this very very very very very very long prefix ensures that the payload is outside the parseable response because it is 105 bytes long%s", "responsebodycode")
	empty := false
	backendLogs.Reset()
	checkRequest(t, "bar.example.com", envoyEndpoint+"/post", "POST", http.StatusOK, &empty, data, "Content-Type", "application/x-www-form-urlencoded")
	checkInLogs(t, 200, http.MethodPost, "/post")
}

func TestE2EResponseBodyLimitReject(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "baz.example.com", envoyEndpoint+"/bytes/80", "GET", http.StatusInternalServerError, &empty, "")
	checkInLogs(t, http.StatusOK, http.MethodGet, "/bytes/80")
}

// Testing some CRS rules
func TestE2ECRSXSSDetection(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/anything?arg=<script>alert(0)</script>", "GET", http.StatusForbidden, &empty, "")
	checkNotInLogs(t, http.MethodGet, "/anything")
}

func TestE2ECRSSQLiDetection(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/post", "POST", http.StatusForbidden, &empty, "1%27%20ORDER%20BY%203--%2B")
	checkNotInLogs(t, http.MethodPost, "/post")
}

func TestE2ECRSTruePositiveUserAgent(t *testing.T) {
	backendLogs.Reset()
	req, err := http.NewRequest("GET", envoyEndpoint+"/anything", nil)
	require.NoError(t, err)
	req.Header.Set("User-Agent", "gobuster/3.2.0 (X11; U; Linux i686; en-US; rv:1.7)")
	req.Header.Set("Host", "foo.example.com")
	req.Header.Set("Accept", "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	checkNotInLogs(t, http.MethodGet, "/anything")
}

func TestE2ECRSTrueNegativeUserAgent(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/anything", "GET", http.StatusOK, &empty, "", "User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36")
	checkInLogs(t, 200, http.MethodGet, "/anything")
}

// Testing per route/virtual host configurations
func TestE2EPerRouteConfigTrueNegative(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/other-waf", "GET", http.StatusNotFound, &empty, "")
	checkInLogs(t, 404, http.MethodGet, "/other-waf")
}

func TestE2EPerRouteConfigOtherWafNotBlock(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/other-waf/admin", "GET", http.StatusNotFound, &empty, "")
	checkInLogs(t, 404, http.MethodGet, "/other-waf/admin")
}

func TestE2EPerRouteConfigTruePositiveRequestHeaderPhase(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/other-waf/other-admin", "GET", http.StatusForbidden, &empty, "")
	checkNotInLogs(t, http.MethodGet, "/other-waf/other-admin")
}

func TestE2EPerRouteTruePositiveRequestBodyPhase(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "foo.example.com", envoyEndpoint+"/other-waf", "POST", http.StatusForbidden, &empty, "evilpayload")
	checkNotInLogs(t, http.MethodPost, "/other-waf")
}

func TestE2EPerVirtualHostConfigTrueNegative(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "foo.vhost-example.com", envoyEndpoint+"/health", "GET", http.StatusOK, &empty, "")
	// uses sse-server as backend so we cant expect logs
}

func TestE2EPerVirtualHostOtherWafNotBlock(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "foo.vhost-example.com", envoyEndpoint+"/health/admin", "GET", http.StatusNotFound, &empty, "")
	// uses sse-server as backend so we cant expect logs
}

func TestE2EPerVirtualHostConfigTruePositiveRequestHeaderPhase(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "foo.vhost-example.com", envoyEndpoint+"/health/vhost-admin", "GET", http.StatusForbidden, &empty, "")
	checkNotInLogs(t, http.MethodGet, "/health/vhost-admin")
}

func TestE2EPerVirtualHostTruePositiveRequestBodyPhase(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "foo.vhost-example.com", envoyEndpoint+"/health", "POST", http.StatusForbidden, &empty, "evilpayload_vhost")
	checkNotInLogs(t, http.MethodPost, "/health")
}

func TestE2EFilesystemRuleTrueNegative(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "custom.example.com", envoyEndpoint+"/anything", "GET", http.StatusOK, &empty, "")
	checkInLogs(t, 200, http.MethodGet, "/anything")
}

func TestE2EFilesystemRuleTruePositive(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "custom.example.com", envoyEndpoint+"/evil", "GET", http.StatusForbidden, &empty, "")
	checkNotInLogs(t, http.MethodGet, "/evil")
}

func TestE2EFilesystemRuleTruePositiveFromOtherFile(t *testing.T) {
	empty := true
	backendLogs.Reset()
	checkRequest(t, "custom.example.com", envoyEndpoint+"/dangerous", "GET", http.StatusForbidden, &empty, "")
	checkNotInLogs(t, http.MethodGet, "/dangerous")
}

func TestE2EFilesystemRuleOtherWafNotBlock(t *testing.T) {
	empty := false
	backendLogs.Reset()
	checkRequest(t, "custom.example.com", envoyEndpoint+"/admin", "GET", http.StatusNotFound, &empty, "")
	checkInLogs(t, 404, http.MethodGet, "/admin")
}
