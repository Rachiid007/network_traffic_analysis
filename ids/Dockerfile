# Dockerfile for the IDS service using the ids_iforest package

FROM python:3.11-slim

# Install dependencies for PyShark (tshark) and attack generation tools
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        tcpdump \
        hping3 \
        wrk \
        iproute2 \
        iputils-ping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package source and configuration into the container
COPY ids_iforest_package /app
COPY config /app/config
COPY README.md /app/

# Install the ids_iforest package into the environment
RUN pip install --no-cache-dir wheel && \
    pip install --no-cache-dir .

# Expose the web UI port
EXPOSE 5000

# Copy entrypoint script and set it as the default command
COPY ids/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]