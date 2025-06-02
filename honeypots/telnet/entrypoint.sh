#!/bin/bash
set -e

# Create log directory
mkdir -p /var/log/honeypot
chown honeypot:honeypot /var/log/honeypot

# Start Telnet honeypot
echo "Starting Telnet honeypot..."
exec python3 /app/telnet_honeypot.py