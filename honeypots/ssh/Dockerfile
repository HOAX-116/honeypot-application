FROM python:3.11-slim

LABEL maintainer="Honeypot Team"
LABEL description="SSH Honeypot Service"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Create honeypot user
RUN useradd -m -s /bin/bash honeypot

# Set up SSH configuration
RUN mkdir -p /var/run/sshd
COPY sshd_config /etc/ssh/sshd_config
RUN ssh-keygen -A

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy honeypot application
COPY ssh_honeypot.py /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# Create log directory
RUN mkdir -p /var/log/honeypot
RUN chown honeypot:honeypot /var/log/honeypot

WORKDIR /app

EXPOSE 22

ENTRYPOINT ["/app/entrypoint.sh"]