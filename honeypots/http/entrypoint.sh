#!/bin/bash
set -e

# Create log directory
mkdir -p /var/log/honeypot
chown honeypot:honeypot /var/log/honeypot

# Start HTTP honeypot
echo "Starting HTTP honeypot..."
exec python3 /app/http_honeypot.py