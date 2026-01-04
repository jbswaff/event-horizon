# Event Horizon Docker Usage

## Building the Image

```bash
docker build -t event-horizon .
```

## Running with Environment Variables

### Single Pi-hole Example

```bash
docker run -d \
  --name event-horizon \
  -p 8080:8080 \
  -e PORT=8080 \
  -e DISABLE_MINUTES=10 \
  -e SHOW_LOG_LINK=true \
  -e PIHOLE_COUNT=1 \
  -e PIHOLE_1_NAME=pihole1 \
  -e PIHOLE_1_URL=http://192.168.1.100:80 \
  -e PIHOLE_1_APP_PASSWORD=your_password_here \
  event-horizon
```

### Multiple Pi-holes Example

```bash
docker run -d \
  --name event-horizon \
  -p 8080:8080 \
  -e PORT=8080 \
  -e DISABLE_MINUTES=10 \
  -e SHOW_LOG_LINK=true \
  -e PIHOLE_COUNT=2 \
  -e PIHOLE_1_NAME=pihole-primary \
  -e PIHOLE_1_URL=http://192.168.1.100:80 \
  -e PIHOLE_1_APP_PASSWORD=password1 \
  -e PIHOLE_2_NAME=pihole-secondary \
  -e PIHOLE_2_URL=http://192.168.1.101:80 \
  -e PIHOLE_2_APP_PASSWORD=password2 \
  event-horizon
```

## Using Docker Compose

### Setup

1. Copy the sample environment file and configure your Pi-hole instances:

```bash
cp .env.sample .env
# Edit .env with your actual Pi-hole URLs and passwords
```

2. Start the service:

```bash
docker compose up -d
```

### Development with Hot Reload

The included `docker-compose.yml` uses `Dockerfile.dev` and mounts `server.py` as a volume. Any changes to `server.py` will automatically reload the server:

```bash
# Start in development mode with live reload
docker compose up

# Or run in background
docker compose up -d

# View logs
docker compose logs -f
```

The development setup includes:
- Volume mount for `server.py` - edit locally and see changes immediately
- `watchfiles` for automatic reload on file changes
- Configuration loaded from `.env` file

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Port to listen on | `8080` |
| `DISABLE_MINUTES` | Minutes to disable protection | `10` |
| `SHOW_LOG_LINK` | Show logs link on main page | `true` |
| `PIHOLE_COUNT` | Number of Pi-hole instances | `1` |
| `PIHOLE_N_NAME` | Friendly name for Pi-hole N | `piholeN` |
| `PIHOLE_N_URL` | Full URL for Pi-hole N | (required) |
| `PIHOLE_N_APP_PASSWORD` | App password for Pi-hole N | (required) |

Replace `N` with the Pi-hole number (1, 2, 3, etc.).

## Viewing Logs

### Docker Run
```bash
docker logs event-horizon
```

### Docker Compose
```bash
docker compose logs -f
```

## Accessing the Service

Open your browser to `http://localhost:8080` (or the port you configured).

## Security Notes

- This service has **NO authentication** and **NO TLS**
- Only expose it on a trusted network
- Use firewall rules to restrict access
- Consider using a reverse proxy with authentication if exposing to a wider network
