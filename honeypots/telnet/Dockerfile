FROM python:3.11-slim

LABEL maintainer="Honeypot Team"
LABEL description="Telnet Honeypot Service"

# Create honeypot user
RUN useradd -m -s /bin/bash honeypot

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy honeypot application
COPY telnet_honeypot.py /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

# Create log directory
RUN mkdir -p /var/log/honeypot
RUN chown honeypot:honeypot /var/log/honeypot

WORKDIR /app

EXPOSE 23

ENTRYPOINT ["/app/entrypoint.sh"]