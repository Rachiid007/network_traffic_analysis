FROM python:3.11-slim
ENV DEBIAN_FRONTEND=noninteractive

# System deps
RUN apt-get update \
 && apt-get install -y --no-install-recommends tshark ca-certificates curl nano jq \
 && rm -rf /var/lib/apt/lists/*

# PATCH: keep packaging tools updated to fixed versions
RUN python -m pip install --no-cache-dir --upgrade pip wheel setuptools==78.1.1

WORKDIR /app

# Local package and config
COPY ./ids_iforest_package/ /app/ids_iforest_package/
RUN pip install --no-cache-dir /app/ids_iforest_package
COPY ./config/ /app/config/
RUN mkdir -p /app/logs /app/models

# Entrypoint
COPY ./services/ids/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
