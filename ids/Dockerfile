# Dockerfile for the IDS service using the ids_iforest package
FROM python:3.11

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        tcpdump \
        iproute2 \
        iputils-ping \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install your ids_iforest package (pyproject at repo root under ids_iforest_package)
COPY ids_iforest_package/pyproject.toml /app/pyproject.toml
COPY ids_iforest_package/ids_iforest /app/ids_iforest
COPY README.md /app/README.md

RUN pip install --no-cache-dir --upgrade pip wheel && \
    pip install --no-cache-dir .

# Config & pre-trained model (mounted as volumes at runtime, but COPY keeps image self-contained)
COPY config /app/config
COPY models /app/models

# Web UI port
EXPOSE 5000

# Entrypoint
COPY ids/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
