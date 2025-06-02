#!/bin/bash
set -e

# Create log directory
mkdir -p /var/log/honeypot
chown honeypot:honeypot /var/log/honeypot

# Start FTP honeypot
echo "Starting FTP honeypot..."
exec python3 /app/ftp_honeypot.py