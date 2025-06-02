#!/bin/bash
set -e

echo "Starting GeoIP enrichment service..."
exec python3 /app/geoip_service.py