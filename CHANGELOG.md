# Changelog

All notable changes to Event Horizon will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2-beta.1] - 2026-01-12

### Added

- **Cancel bypass feature**: "Resume Blocking Now" button allows users to end bypass early
- **Active bypass indicator**: Main page shows countdown when bypass is active for the visitor
- **API response logging**: All Pi-hole API calls logged to `api.log` for debugging
- **Log rotation**: Automatic rotation at configurable size (default 10MB) and age (default 7 days)
- **Session caching**: Reuses Pi-hole sessions to reduce "API seats exceeded" errors
- **`/health` JSON endpoint**: For Docker healthchecks and monitoring tools
- **Dark mode CSS**: Respects system `prefers-color-scheme` preference
- **Tabbed log viewer**: Switch between Request logs and API logs in web UI
- **Version display**: Shows version in web UI footer and `X-Event-Horizon-Version` response header
- **Favicon**: Inline SVG shield icon (no more 404s for favicon requests)
- **Startup configuration banner**: Logs all settings at startup for debugging
- **IPv6 normalization**: Consistent handling of IPv6 address formats
- **Dockerfile improvements**: Non-root user, OCI labels, built-in healthcheck
- **Rate limiting**: Configurable hourly request limit per client (default 10/hour)

### Fixed

- **Client lookup bug**: Now correctly checks the `client` field (Pi-hole's primary identifier)
- **Memory leak**: `LAST_PRESS_BY_IP` cache now auto-cleans every 5 minutes
- **XSS vulnerability**: All user-facing content now HTML-escaped
- **Restore logging**: Timer callbacks now log success/failure for debugging
- **Session invalidation**: Cached sessions are invalidated on auth errors

### Changed

- Version constant centralized (no longer hardcoded in multiple places)
- Improved error messages for API session limits

### Removed

- Unused `_utf16be_hex()` function
- Unused `api_disable_for()` function

### New Configuration Options

```bash
EH_API_LOG_ENABLED=true      # Enable API response logging
EH_LOG_MAX_SIZE_MB=10        # Max log file size before rotation
EH_LOG_MAX_AGE_DAYS=7        # Max log age before rotation
EH_SESSION_CACHE_TTL=300     # Session cache duration (seconds)
EH_RATE_LIMIT_REQUESTS=10    # Max requests per window (0 to disable)
EH_RATE_LIMIT_WINDOW=3600    # Rate limit window in seconds
```

## [0.3.1-beta.1] - 2026-01-11

### Added

- **SSL/TLS certificate support**: Configurable certificate verification
- **Retry logic with exponential backoff**: Automatic retry on network/SSL/timeout errors
- **Pi-hole version detection**: Validates Pi-hole v6+ compatibility
- **User-Agent header**: All requests include `User-Agent: Event-Horizon/{version}`
- **Configurable API timeout**: Increased default from 5s to 15s

### Fixed

- **Version endpoint**: Changed from `/api/version` to `/api/info/version`
- **Version parsing**: Correctly parses Pi-hole v6 version response format
- **Authentication order**: Now authenticates before version check (endpoint requires auth)
- **Client identifier**: Uses plain IP address instead of UTF-16BE hex encoding

### New Configuration Options

```bash
EH_VERIFY_SSL=true           # SSL certificate verification
EH_API_TIMEOUT=15            # Request timeout in seconds
EH_API_MAX_RETRIES=3         # Number of retry attempts
EH_API_RETRY_DELAY=1         # Initial retry delay (exponential backoff)
```

## [0.3.0-beta.1] - 2026-01-03

### Added

- Per-client bypass via Pi-hole group membership
- Multi Pi-hole instance support
- Reverse proxy support with X-Forwarded-For
- Request logging
- Health status display on main page
- Cooldown between requests

### Changed

- Migrated from global disable to per-client bypass
- Improved error handling and display

## [0.2.0-beta.1]

### Added

- Initial Docker support
- Basic web interface
- Pi-hole v6 API integration

---

**Baseline:** Each version builds upon the previous release.
