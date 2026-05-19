# AGENTS.md

## Build
```bash
make build              # → build/coraza-waf.so  (buildmode=c-shared)
make performanceBuild   # Docker CGO cross-compile with libinjection+re2
make lint               # golangci-lint v2, all linters enabled, gofmt+goimports
make start-watcher      # build → docker compose up → auto-restart on .so change
```

## Testing — no unit tests, only integration
```bash
make ftw     # CRS regression via go-ftw (requires Docker)
make e2e     # Go testcontainers with real Envoy (requires Docker)
make ftw     && make e2e                 # full suite
FTW_INCLUDE=920410 make ftw             # single rule
FTW_FAILFAST=1 make ftw                 # fail-fast
make build && go test -v ./tests/e2e/...  # verbose e2e
```

Both require `make build` first. E2E helpers: `checkRequest()`, `checkInLogs()`, `checkNotInLogs()` in `tests/e2e/e2e_test.go`.

## Config — native YAML (not JSON strings)

```yaml
value:
  directives:
    waf1:
      simple_directives:
        - "Include @coraza-setup"
        - "Include @owasp_crs/*.conf"
  default_directive: "waf1"
  host_directive_map:
    "foo.example.com": "waf1"
```

Config arrives as `xds.TypedStruct` → `structpb.Value`. Parsed in `internal/config/config.go`. The `Merge()` method simply returns child config (per-route overrides parent entirely).

## Architecture
```
main.go                         → Register plugin + config.Parser
internal/config/config.go       → Parse TypedStruct, build WafMaps
internal/filter/filter.go       → Filter implementing 4 Envoy phases
internal/filter/phases.go       → PhaseRequestHeader/Body, PhaseResponseHeader/Body
internal/filter/connection_type.go → HTTP / HTTP Tunnel / WebSocket state machine
internal/logging/               → slog-based structured logging wrapper
internal/libinjection/          → CGO libinjection registration (performance build)
internal/re2/                   → CGO re2 registration (performance build)
```

`Configuration` struct: `directives` (raw SecLang), `DefaultDirective`, `HostDirectiveMap`, `WafMaps` (instantiated), `LogFormat`.

## Key conventions & quirks

- **Copyright header required**: `Copyright © 2023 Axkea, spacewander` + `Copyright © 2025 United Security Providers AG, Switzerland` + `SPDX-License-Identifier: Apache-2.0`
- **Build tags**: `coraza.rule.multiphase_evaluation,memoize_builders` (default). Performance adds `libinjection_cgo,re2_cgo`.
- **Import order**: stdlib → third-party → `coraza-waf/internal/...`
- **No panic** outside the type assertion in `filterFactory()` in `main.go`
- **Log messages** truncated at 250 chars (`maxMessageSize`)
- **HTTP status codes**: prefer `http.StatusXxx` constants
- **CRS embedded** in `internal/config/coreruleset/`, included via `@coraza-setup`, `@crs-setup`, `@owasp_crs/*.conf`
- **Docker compose** uses `GODEBUG=cgocheck=0` env var
- **SSE tests** in `tests/e2e/e2e_sse_test.go` with a dedicated SSE server in `tests/e2e/sse-server/`
- **Host lookup order**: (1) exact Host header match, (2) stripped port match, (3) `default_directive`

## CI pipeline (GitHub Actions)
```
lint → build → ftw → e2e → govulncheck
```
PRs also require a changelog entry (enforced by `dangoslen/changelog-enforcer`, skip with `skip_changelog` label).
