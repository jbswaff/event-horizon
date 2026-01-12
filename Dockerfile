FROM python:3.12-slim

# Labels for container metadata
LABEL org.opencontainers.image.title="Event Horizon"
LABEL org.opencontainers.image.description="Per-client ad-blocking bypass for Pi-hole v6"
LABEL org.opencontainers.image.source="https://github.com/jbswaff/event-horizon"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user
RUN groupadd -r eventhor && useradd -r -g eventhor eventhor

# Create log directory with correct permissions
RUN mkdir -p /var/log/event-horizon && chown eventhor:eventhor /var/log/event-horizon

WORKDIR /app
COPY --chown=eventhor:eventhor server.py /app/server.py

# Switch to non-root user
USER eventhor

ENV EH_PORT=8080
EXPOSE 8080

# Healthcheck using the /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health', timeout=5)" || exit 1

CMD ["python", "/app/server.py"]
