# Changelog

## [1.0.0] - In progress

_First release._

### Changed
- Update go to version 1.24.4 ([#14](https://github.com/united-security-providers/coraza-envoy-go-filter/pull/14)) ([daum3ns](https://github.com/daum3ns))
- Return status code from coraza interruption ([#11](https://github.com/united-security-providers/coraza-envoy-go-filter/issues/11)) ([daum3ns](https://github.com/daum3ns))
- Update Core Rule Set to version 4.14, update envoy to v1.34 (#X) ([daum3ns](https://github.com/daum3ns))
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


[1.0.0]: https://github.com/united-security-providers/coraza-envoy-go-filter/tags/1.0.0 
