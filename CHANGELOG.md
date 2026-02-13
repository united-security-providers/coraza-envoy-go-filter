# Changelog

## [Unreleased]

### Added
- Set the memoize_builders flag to reduce memory consumption in deployments that launch several coraza instances. ([#42](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/42)) ([daum3ns](https://github.com/daum3ns))
- Add a new build target for improved performance on larger payloads. ([#45](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/45)) ([kabbohus](https://github.com/HusseinKabbout))

### Changed
- Update go to version 1.24.11 ([#40](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/40)) ([daum3ns](https://github.com/daum3ns)) ([48](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/48))
- Update envoy to 1.37.0 ([#37](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/37)) ([#49](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/49)) ([56](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/56))
- Update protobuf to 1.36.11 ([#37](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/37)) ([54](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/54))
- Migrate form `mage` to `make` ([#62](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/62)) ([kabbohus](https://github.com/HusseinKabbout))

### Fixed
- Fix HTTP headers arrive at backend despite the request being blocked in the later phase ([#61](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/61))([daum3ns](https://github.com/daum3ns))

### Known Issues
- A bug in Coraza results in a wrong HTTP status code returned, if `SecResponseBodyLimit` is reached and `SecResponseBodyLimitAction` is set to `Reject`. Coraza incorrectly returns HTTP 413 instead of HTTP 500. ([corazawaf/coraza#1377](https://github.com/corazawaf/coraza/issues/1377))

## [v1.1.1] - 2025-09-18

### Changed
- Update go to version 1.24.6 ([#32](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/32)) ([daum3ns](https://github.com/daum3ns))

## [v1.1.0] - 2025-09-18

### Changed
- Improved log messages ([#31](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/31)) ([daum3ns](https://github.com/daum3ns))
- Update envoy to 1.35.3 ([#27](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/27)) ([daum3ns](https://github.com/daum3ns))
- Update CRS to version 4.18.0 ([#23](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/23)) ([#26](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/26)) ([daum3ns](https://github.com/daum3ns)) ([kabbohus](https://github.com/HusseinKabbout))

### Known Issues
- A bug in Coraza results in a wrong HTTP status code returned, if `SecResponseBodyLimit` is reached and `SecResponseBodyLimitAction` is set to `Reject`. Coraza incorrectly returns HTTP 413 instead of HTTP 500. ([corazawaf/coraza#1377](https://github.com/corazawaf/coraza/issues/1377))

## [v1.0.0] - 2025-07-15

_First release._

### Changed
- Update CRS to version 4.16.0 ([#20](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/20)) ([daum3ns](https://github.com/daum3ns))
- Make log format configurable ([#9](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/9)) ([daum3ns](https://github.com/daum3ns))
- Update go to version 1.24.4 ([#14](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/14)) ([daum3ns](https://github.com/daum3ns))
- Return status code from coraza interruption ([#11](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/11)) ([daum3ns](https://github.com/daum3ns))
- Update envoy to v1.34 (#X) ([daum3ns](https://github.com/daum3ns))
- Update dependencies: coraza v3.3.3 and protobuf v1.36.6 (#X) ([daum3ns](https://github.com/daum3ns))


### Added
- Add changelog ([#8](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/8)) ([daum3ns](https://github.com/daum3ns))

### Fixed
- Fix filter disrupts websocket connections ([#18](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/18)) ([daum3ns](https://github.com/daum3ns))
- Fix wrong status code returned when reaching body limits ([#6](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/6)) ([daum3ns](https://github.com/daum3ns))
- Fix wrong status code returned ([#5](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/5)) ([daum3ns](https://github.com/daum3ns))
- Fix avoid response inspection if SecResponseBodyAccess is off ([#4](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/4/)) ([Armin Abfalterer](https://github.com/arminabf))
- Fix go-ftw testbench (#X) ([daum3ns](https://github.com/daum3ns))
- Fix rule exclusion via SecAction to not working (#X) ([daum3ns](https://github.com/daum3ns))

### Known Issues
- A bug in Coraza results in a wrong HTTP status code returned, if `SecResponseBodyLimit` is reached and `SecResponseBodyLimitAction` is set to `Reject`. Coraza incorrectly returns HTTP 413 instead of HTTP 500. ([corazawaf/coraza#1377](https://github.com/corazawaf/coraza/issues/1377))

[v1.1.1]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.1.1
[v1.1.0]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.1.0
[v1.0.0]: https://github.com/united-security-providers/coraza-envoy-go-filter/releases/tag/v1.0.0
