FROM python:3.11-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends tshark ca-certificates curl nano jq \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install your local package so ids-iforest-... entrypoints exist
COPY ./ids_iforest_package/ /app/ids_iforest_package/

RUN pip install --no-cache-dir /app/ids_iforest_package

# Copy config; models and logs are mounted at runtime
COPY ./config/ /app/config/
RUN mkdir -p /app/logs /app/models

COPY ./services/ids/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
