#!/bin/bash
set -e

echo "Starting alert management service..."

# Wait for Elasticsearch to be ready
echo "Waiting for Elasticsearch..."
while ! curl -s http://elasticsearch:9200/_cluster/health >/dev/null 2>&1; do
    echo "Waiting for Elasticsearch to be ready..."
    sleep 5
done

echo "Elasticsearch is ready, starting alert service..."
exec python3 /app/alert_service.py