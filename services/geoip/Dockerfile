FROM python:3.11-slim

LABEL maintainer="Honeypot Team"
LABEL description="GeoIP Enrichment Service"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create app user
RUN useradd -m -s /bin/bash app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY geoip_service.py /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# Create directories
RUN mkdir -p /app/geoip
RUN chown -R app:app /app

WORKDIR /app

ENTRYPOINT ["/app/entrypoint.sh"]