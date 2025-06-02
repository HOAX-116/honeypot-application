#!/bin/bash
set -e

# Create log directory
mkdir -p /var/log/honeypot
chown honeypot:honeypot /var/log/honeypot

# Create SSH banner
cat > /etc/ssh/banner << 'EOF'
Ubuntu 20.04.3 LTS
Unauthorized access is prohibited.
EOF

# Start SSH honeypot
echo "Starting SSH honeypot..."
exec python3 /app/ssh_honeypot.py