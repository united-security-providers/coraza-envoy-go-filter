BUILD-TAGS := coraza.rule.multiphase_evaluation,memoize_builders
GOLANG-CI-LINT-VERSION := v2.8.0
BUILD-DIRECTORY := ./build

.PHONY: build
build:
	mkdir -p $(BUILD-DIRECTORY)
	go build -o $(BUILD-DIRECTORY)/coraza-waf.so -buildmode=c-shared -tags=$(BUILD-TAGS)

performanceBuild:
	mkdir -p $(BUILD-DIRECTORY)
	docker build --target build --build-arg BUILD-TAGS=$(BUILD-TAGS),libinjection_cgo,re2_cgo . -t coraza-waf-builder
	docker cp $$(docker create coraza-waf-builder):/src/coraza-waf.so $(BUILD-DIRECTORY)

# Build the envoy image that we are going to use for tests and examples
buildEnvoy:
	docker build --target envoy . -t coraza-waf-envoy

runExample: build buildEnvoy teardownExample
	docker compose --file example/docker-compose.yml up -d

teardownExample:
	docker compose --file example/docker-compose.yml down

e2e: clean build buildEnvoy
	docker compose --file tests/e2e/docker-compose.yml up --abort-on-container-exit tests; \
	docker compose --file tests/e2e/docker-compose.yml down

ftw: clean build buildEnvoy
	docker compose --file tests/ftw/docker-compose.yml run --rm ftw-crs; \
	docker compose --file tests/ftw/docker-compose.yml down

clean:
	docker compose --file example/docker-compose.yml down
	docker compose --file tests/e2e/docker-compose.yml down
	docker compose --file tests/ftw/docker-compose.yml down
	rm -rf $(BUILD-DIRECTORY)/*

lint:
	go run "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANG-CI-LINT-VERSION)" run
