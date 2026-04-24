BUILD-TAGS := coraza.rule.multiphase_evaluation
GOLANG-CI-LINT-VERSION := v2.10.1
BUILD-DIRECTORY := ./build

.PHONY: build
build:
	mkdir -p $(BUILD-DIRECTORY)
	go build -o $(BUILD-DIRECTORY)/coraza-waf.so -buildmode=c-shared -tags=$(BUILD-TAGS)

performanceBuild:
	mkdir -p $(BUILD-DIRECTORY)
	docker build --target build --build-arg BUILD_TAGS=$(BUILD-TAGS),libinjection_cgo,re2_cgo . -t coraza-waf-builder
	docker cp $$(docker create coraza-waf-builder):/src/coraza-waf.so $(BUILD-DIRECTORY)

# Build the envoy image that we are going to use for tests and examples
buildTestEnvoy:
	docker build --target envoy . -t coraza-waf-envoy

# Build SSE server image for e2e tests
buildTestSSE:
	docker build -t e2e-sse-server tests/e2e/sse-server/

start-watcher: clean build buildTestEnvoy
	docker compose down
	docker compose up -d
	@echo "Watching coraza-waf.so for changes..."
	@while inotifywait --quiet -e create -e attrib -e modify $(BUILD-DIRECTORY); do \
		echo "Change detected! Restarting envoy..." && \
		docker compose restart envoy || docker compose up -d envoy; \
	done

e2e: clean build buildTestEnvoy buildTestSSE
	go test -v ./tests/e2e/...


ftw: clean build buildTestEnvoy
	docker compose --file tests/ftw/docker-compose.yml up --build ftw-crs --exit-code-from ftw-crs; \
	EXIT_CODE=$$?; \
	docker compose --file tests/ftw/docker-compose.yml down; \
	exit $$EXIT_CODE

clean:
	docker compose down
	docker compose --file tests/ftw/docker-compose.yml down
	docker rmi -f coraza-waf-builder coraza-waf-envoy ftw-ftw-crs e2e-sse-server e2e-tests envoy-coraza
	rm -rf $(BUILD-DIRECTORY)/*
	go clean -testcache

lint:
	go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANG-CI-LINT-VERSION)" run
