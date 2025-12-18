# Release Notes - LDQ JDBC Driver

## Version 1.1.1

### Changed
- Updated Jackson to `2.21.7`.

### Fixed
- The local OAuth callback server uses TLS 1.2.

## Version 1.1.0

### Added
- HTTP, in addition to HTTPS, for the local OAuth authorization-code callback server.
- Query logs identify this driver by name and version.

## Version 1.0.3

### Added
- Access-token authentication (`wd.authn.accessToken`).
- `wd.ldqUseCase` workload property.

### Fixed
- Connection failures on long-lived pooled connections.

## Version 1.0.0

Initial open source release of the Workday Live Data Query JDBC driver.

Partners previously using `com.workday.dataservice:data-service-driver` should switch to
`com.workday.ldq.jdbc:ldq-jdbc-driver:1.0.0` (or `:all` for the fat JAR). JDBC URL and
`wd.authn.*` properties are unchanged.
