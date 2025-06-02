FROM python:3.11-slim

LABEL maintainer="Honeypot Team"
LABEL description="API Gateway Service"

# Create app user
RUN useradd -m -s /bin/bash app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY api_gateway.py /app/
COPY entrypoint.sh /app/
RUN chmod +x /app/entrypoint.sh

RUN chown -R app:app /app

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["/app/entrypoint.sh"]