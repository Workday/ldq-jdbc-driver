# Workday Live Data Query (LDQ) JDBC Driver

Custom Workday JDBC driver with OAuth 2.0 support. Thin wrapper over the Trino JDBC driver for `jdbc:workday://` URLs.

Built with Gradle (wrapper included). Dependencies resolve from **Maven Central**.

## Features

- **OAuth 2.0 JWT Bearer Grant Type**: RFC 7523 JWT Bearer Grant for service-account authentication with a private key
- **OAuth 2.0 Authorization Code Grant Type**: RFC 6749 Authorization Code Grant with and without PKCE (RFC 7636) for interactive browser-based authentication
- **Direct Access Token**: Supports connecting with a pre-issued access token, without performing any token exchange
- **Automatic Token Management**: Creates JWT assertions or handles browser-based OAuth flows and requests access tokens

## Requirements

- JDK 11+
- Gradle Wrapper (included)

## Build

```bash
./gradlew build          # unit tests + lean JAR + fat JAR + sources/javadoc JARs
./gradlew shadowJar      # fat JAR only
./gradlew jar            # lean JAR only
./gradlew javadoc        # HTML API reference under build/docs/javadoc/
./gradlew javadocJar     # javadoc JAR only (also produced by build)
./gradlew manifestValidationTest   # checks fat JAR manifest / LICENSE / NOTICE
```

Artifacts under `build/libs/`:

| Artifact | Description |
|----------|-------------|
| `ldq-jdbc-driver-<version>.jar` | **Lean** JAR (bring deps via Maven/Gradle) |
| `ldq-jdbc-driver-<version>-all.jar` | **Fat** JAR (shaded; DBeaver / Tableau / drop-in classpath) |
| `ldq-jdbc-driver-<version>-sources.jar` | Sources |
| `ldq-jdbc-driver-<version>-javadoc.jar` | Javadoc (for Maven publish / IDE offline docs) |

HTML Javadoc is written to `build/docs/javadoc/` when you run `./gradlew javadoc`.

## Testing

Unit tests run on **JDK 11** by default. The default `test` task excludes live integration tests and fat-JAR manifest validation (those have dedicated tasks below).

### Run all unit tests

```bash
./gradlew test
```

This is also run as part of `./gradlew build`.

### Fat JAR validation

Requires the shadow JAR to be built first (the task depends on `shadowJar`):

```bash
./gradlew manifestValidationTest
```

### Optional: run unit tests on other JDK versions

```bash
./gradlew testOnJava17
./gradlew testOnJava21
./gradlew testOnJava25
```

### Run a single test class

```bash
./gradlew test --tests "com.workday.ldq.jdbc.api.LDQJdbcDriverTest"
```

### Run a single test case

```bash
./gradlew test --tests "com.workday.ldq.jdbc.api.LDQJdbcDriverTest.testAcceptsURL"
```

### Run all tests in a package

```bash
./gradlew test --tests "com.workday.ldq.jdbc.impl.oauth.*"
```

### Integration tests

`com.workday.ldq.jdbc.integration.*` is **excluded** from the default `test` task. Those tests expect a reachable LDQ endpoint (see `DriverConnectionIntegrationTest`). Fork contributors extending the driver typically rely on unit tests above; run integration tests only when you have a suitable local or test environment.

## Maven / Gradle coordinates (when published)

```gradle
implementation("com.workday.ldq.jdbc:ldq-jdbc-driver:1.1.2")
// fat:
implementation("com.workday.ldq.jdbc:ldq-jdbc-driver:1.1.2:all")
```

## Usage

```java
Class.forName("com.workday.ldq.jdbc.api.LDQJdbcDriver");

Properties props = new Properties();
// set wd.authn.* OAuth properties as required

String url = "jdbc:workday://<ldq-host>:<port>/catalog/schema";
Connection connection = DriverManager.getConnection(url, props);
```

## Configuration properties

Properties are passed to `DriverManager.getConnection(url, props)` (or your JDBC client's connection settings). OAuth properties are required to obtain an access token; Trino properties tune the underlying Trino JDBC connection.

### OAuth 2.0 properties

Used to configure the OAuth 2.0 authentication flow. Set `wd.authn.authModel` to choose the grant type; other properties depend on that model.

| Property | Description | Required in Grant Type |
|----------|-------------|------------------------|
| `wd.authn.authModel` | `JWT_BEARER`, `AUTHORIZATION_CODE`, `AUTHORIZATION_CODE_PKCE`, or `ACCESS_TOKEN` (default: `JWT_BEARER`) | Optional |
| `wd.authn.accessTokenEndpoint` | OAuth 2.0 token endpoint URL | All except Access Token |
| `wd.authn.clientId` | OAuth 2.0 client ID | All except Access Token |
| `wd.authn.clientSecret` | OAuth 2.0 client secret | Auth Code only |
| `wd.authn.isu` | JWT subject (service account / ISU username) | JWT Bearer |
| `wd.authn.privateKey` | Private key in PEM format for signing JWT assertions | JWT Bearer — provide **one of** `privateKey` or `privateKeyFilePath` |
| `wd.authn.privateKeyFilePath` | Absolute path to a PEM file containing the private key | JWT Bearer — provide **one of** `privateKey` or `privateKeyFilePath` |
| `wd.authn.authorizationEndpoint` | OAuth 2.0 authorization endpoint URL | Auth Code & Auth Code PKCE |
| `wd.authn.redirectUrl` | Redirect URL for the authorization callback (e.g. `https://localhost:8888/callback`) | Auth Code & Auth Code PKCE |
| `wd.authn.accessToken` | Pre-issued access token to use directly, without performing a token exchange | Access Token only |

### Trino JDBC properties

Optional. Passed through to the underlying Trino JDBC driver after OAuth completes.

| Property | Description |
|----------|-------------|
| `wd.http.timeout` | HTTP request timeout for Trino calls (e.g. `30s`, `1m`, `1m30s`; default: `30s`) |
| `wd.sessionProperties` | Trino session properties as comma-separated `key:value` pairs (e.g. `key1:val1,key2:val2`) |

### Connection with OAuth 2.0 Grant Flows

#### JWT Bearer Grant Flow

1. **JWT Assertion Creation**: The driver creates a JWT assertion using your private key.
2. **Token Request**: Sends the JWT assertion to the OAuth 2.0 token endpoint.
3. **Access Token**: Receives an access token from the OAuth server.
4. **Trino Connection**: Uses the access token to authenticate with Trino.

#### Authorization Code Grant Flow

1. **Browser Authorization**: Opens browser to authorization endpoint.
2. **User Authentication**: User authenticates and authorizes the application.
3. **Authorization Code**: Receives authorization code via redirect callback.
4. **Token Exchange**: Driver exchanges authorization code + client secret for access token.
5. **Trino Connection**: Uses the access token to authenticate with Trino.

> Requires `wd.authn.clientSecret`. Set `wd.authn.authModel=AUTHORIZATION_CODE`.

#### Authorization Code Grant Flow (with PKCE)

1. **Code Verifier Generation**: The driver generates a cryptographically random code verifier.
2. **Code Challenge Creation**: Creates a SHA-256 hash of the code verifier (code challenge).
3. **Browser Authorization**: Opens browser to authorization endpoint with code challenge.
4. **Authorization Code**: User authenticates and authorizes; receives authorization code via redirect.
5. **Token Exchange**: Driver exchanges authorization code + code verifier for access token.
6. **Trino Connection**: Uses the access token to authenticate with Trino.

> Does **not** require `wd.authn.clientSecret`. Set `wd.authn.authModel=AUTHORIZATION_CODE_PKCE` (recommended for public clients).

#### Direct Access Token Flow

1. **Trino Connection**: Uses the supplied `wd.authn.accessToken` value directly to authenticate with Trino.

> Does not support refreshing; supply a new access token and reconnect when it expires. Set `wd.authn.authModel=ACCESS_TOKEN`.

Example (JWT Bearer + longer query timeout):

```properties
wd.authn.authModel=JWT_BEARER
wd.authn.accessTokenEndpoint=https://YOUR_TENANT.myworkday.com/ccx/oauth2/YOUR_TENANT/token
wd.authn.clientId=YOUR_CLIENT_ID
wd.authn.isu=YOUR_ISU_USERNAME
wd.authn.privateKeyFilePath=/path/to/private-key.pem
wd.http.timeout=2m
```

See `RELEASE_NOTES.md`, `LICENSE`, and `NOTICE`.
