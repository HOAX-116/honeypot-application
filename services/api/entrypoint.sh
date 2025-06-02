#!/bin/bash
set -e

echo "Starting API Gateway service..."
exec gunicorn --bind 0.0.0.0:8080 --workers 2 --timeout 120 api_gateway:app