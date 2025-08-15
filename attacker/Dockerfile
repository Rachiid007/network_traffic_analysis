# Dockerfile for the attacker service

FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        hping3 \
        wrk \
        iproute2 \
        iputils-ping && \
    rm -rf /var/lib/apt/lists/*

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

CMD ["/entrypoint.sh"]
