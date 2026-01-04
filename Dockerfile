FROM python:3.11-slim

# Create app directory
WORKDIR /app

# Create necessary directories
RUN mkdir -p /var/log/event-horizon && \
    chmod 0755 /var/log/event-horizon

# Copy server script
COPY server.py /app/server.py
RUN chmod +x /app/server.py

# Environment variables with defaults
ENV PORT=8080 \
    DISABLE_MINUTES=10 \
    SHOW_LOG_LINK=true \
    PIHOLE_COUNT=1

# Expose the server port
EXPOSE 8080

# Run the server
CMD ["/usr/local/bin/python3", "/app/server.py"]
