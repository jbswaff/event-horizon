# Event Horizon

Per-client ad-blocking bypass for Pi-hole v6. Allows individual devices to temporarily pause ad blocking without affecting other users or devices on the network.

## Features

- **Simple user interface**: The web UI presents a single pushbutton for for the ease of non-technical users
- **Per-client bypass**: Only the requesting device gets ad blocking paused
- **Automatic restore**: Filtering resumes automatically after the configured duration
- **Multi Pi-hole support**: Works with multiple Pi-hole instances simultaneously
- **Cancel anytime**: Users can resume blocking early with one click
- **Dark mode UI**: Respects system color scheme preference
- **Session caching**: Reduces API calls and avoids session limits
- **API logging**: Full request/response logging for debugging
- **Health endpoint**: JSON health status for monitoring and Docker healthchecks

## Requirements

- Pi-hole v6 or later
- Docker (recommended) or Python 3.10+

## Quick Start

### Docker Compose (Recommended)

1. Create a `compose.yaml`:

```yaml
services:
  event-horizon:
    image: ghcr.io/jbswaff/event-horizon:latest
    container_name: event-horizon
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      EH_PIHOLE_COUNT: "1"
      EH_PIHOLE_1_NAME: "pihole"
      EH_PIHOLE_1_URL: "http://192.168.1.2"
      EH_PIHOLE_1_APP_PASSWORD: "pihole1-app-password"
```

2. Start the container:

```bash
docker compose up -d
```

3. Access the web interface at `http://your-server:8080`

### Getting Your Pi-hole App Password

1. Log into your Pi-hole admin interface
2. Go to **Settings** > **API** > **App Password**
3. Generate a new app password
4. Copy the password and use it for `EH_PIHOLE_X_APP_PASSWORD`
5. Store the password in a safe location; it will not be displayed again!

## Configuration

All configuration is done via environment variables (prefix with `EH_`).

### Required Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `EH_PIHOLE_COUNT` | Number of Pi-hole instances | `1` |
| `EH_PIHOLE_X_NAME` | Display name for Pi-hole X | `piholeX` |
| `EH_PIHOLE_X_URL` | URL for Pi-hole X (e.g., `http://192.168.1.2`) | - |
| `EH_PIHOLE_X_APP_PASSWORD` | App password for Pi-hole X | - |

### Optional Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `EH_PORT` | Web server port | `8080` |
| `EH_DISABLE_MINUTES` | Bypass duration in minutes | `10` |
| `EH_COOLDOWN_SECONDS` | Minimum time between requests per client | `3` |
| `EH_BYPASS_GROUP_NAME` | Name of the Pi-hole group for bypassed clients | `Event-Horizon-Bypass` |

### Reverse Proxy Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `EH_TRUST_PROXY` | Trust X-Forwarded-For headers | `false` |
| `EH_TRUSTED_PROXY_NETS` | Trusted proxy networks (comma-separated CIDRs) | `10.0.0.0/8,192.168.0.0/16` |

### API Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `EH_VERIFY_SSL` | Verify SSL certificates for Pi-hole connections | `true` |
| `EH_API_TIMEOUT` | API request timeout in seconds | `15` |
| `EH_API_MAX_RETRIES` | Number of retry attempts for failed requests | `3` |
| `EH_API_RETRY_DELAY` | Initial retry delay in seconds (exponential backoff) | `1` |
| `EH_SESSION_CACHE_TTL` | Session cache duration in seconds | `300` |

### Logging Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `EH_SHOW_LOG_LINK` | Show link to logs on main page | `true` |
| `EH_LOG_DIR` | Log directory path | `/var/log/event-horizon` |
| `EH_API_LOG_ENABLED` | Enable API request/response logging | `true` |
| `EH_LOG_MAX_SIZE_MB` | Max log file size before rotation | `10` |
| `EH_LOG_MAX_AGE_DAYS` | Max log age before rotation | `7` |
| `EH_HEALTH_CACHE_SECONDS` | Health check cache duration | `5` |

### Rate Limiting Settings

| Variable | Description | Default |
|----------|-------------|---------|
| `EH_RATE_LIMIT_REQUESTS` | Max bypass requests per time window (0 to disable) | `10` |
| `EH_RATE_LIMIT_WINDOW` | Rate limit window in seconds | `3600` |

## Multi Pi-hole Setup

For redundant Pi-hole setups, configure multiple instances:

```yaml
environment:
  EH_PIHOLE_COUNT: "2"

  EH_PIHOLE_1_NAME: "pihole-primary"
  EH_PIHOLE_1_URL: "http://192.168.1.2"
  EH_PIHOLE_1_APP_PASSWORD: "pihole1-app-password"

  EH_PIHOLE_2_NAME: "pihole-secondary"
  EH_PIHOLE_2_URL: "http://192.168.1.3"
  EH_PIHOLE_2_APP_PASSWORD: "pihole2-app-password"
```

## Reverse Proxy Configuration

### Nginx

```nginx
server {
    listen 80;
    server_name adblock.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Enable proxy trust in Event Horizon:

```yaml
environment:
  EH_TRUST_PROXY: "true"
  EH_TRUSTED_PROXY_NETS: "127.0.0.1/32,10.0.0.0/8"
```

### Traefik

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.event-horizon.rule=Host(`adblock.example.com`)"
  - "traefik.http.services.event-horizon.loadbalancer.server.port=8080"
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main web interface |
| `/disable` | POST | Pause ad blocking for the requesting client |
| `/cancel` | POST | Resume ad blocking early |
| `/health` | GET | JSON health status |
| `/logs` | GET | View request logs |
| `/logs?type=api` | GET | View API logs |

### Health Endpoint Response

```json
{
  "status": "healthy",
  "version": "0.3.2-beta.1",
  "piholes": [
    {
      "name": "pihole1",
      "healthy": true,
      "status": "healthy",
      "version": " (v6.3)"
    }
  ],
  "timestamp": "2026-01-12T02:34:11Z"
}
```

## Docker Healthcheck

The container includes a built-in healthcheck that queries the `/health` endpoint every 30 seconds.

```bash
# Check container health status
docker inspect --format='{{.State.Health.Status}}' event-horizon
```

## Troubleshooting

### "Unable to determine Pi-hole version"

- Ensure Pi-hole is running v6 or later
- Verify the URL is correct and accessible from the Event Horizon container
- Check that the app password is valid

### "API session limit reached"

- Event Horizon caches sessions to minimize this issue
- Increase `EH_SESSION_CACHE_TTL` if it persists
- Check Pi-hole's `webserver.api.max_sessions` setting

### SSL Certificate Errors

For Pi-hole with self-signed certificates:

```yaml
environment:
  EH_VERIFY_SSL: "false"
```

### View Logs

```bash
# Container logs
docker logs event-horizon

# Request logs
docker exec event-horizon cat /var/log/event-horizon/requests.log

# API logs
docker exec event-horizon cat /var/log/event-horizon/api.log
```

## How It Works

1. User visits Event Horizon and clicks "Pause Ad Blocking"
2. Event Horizon authenticates with each configured Pi-hole
3. Creates/updates a client entry for the user's IP address
4. Moves the client to the "Event-Horizon-Bypass" group (which has no blocklists)
5. Starts a timer to restore the original group membership
6. When the timer expires (or user clicks "Resume"), the client is moved back

## Security Considerations

- The container runs as a non-root user
- App passwords are not logged (only in POST body to auth endpoint)
- XSS protection via HTML escaping
- Rate limiting via cooldown period

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or pull request on GitHub.
