#!/bin/bash
set -e

echo "Starting health monitoring service..."
exec python3 /app/health_monitor.py