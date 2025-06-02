# Multi-Service Cybersecurity Honeypot System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS Free Tier](https://img.shields.io/badge/AWS-Free%20Tier%20Compatible-orange.svg)](https://aws.amazon.com/free/)
[![Docker](https://img.shields.io/badge/Docker-Compose%20Ready-blue.svg)](https://docs.docker.com/compose/)
[![Terraform](https://img.shields.io/badge/Terraform-Infrastructure%20as%20Code-purple.svg)](https://terraform.io/)

A comprehensive, production-ready honeypot system designed for cybersecurity research and threat detection. Deploy multiple service honeypots with complete infrastructure automation, capture attacker behavior, perform geolocation analysis, and visualize threats in real-time using the ELK stack.

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        AWS EC2 Instance (t2.micro)             │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
│  │   Honeypot      │  │   ELK Stack     │  │   GeoIP         │ │
│  │   Services      │  │                 │  │   Analysis      │ │
│  │                 │  │ • Elasticsearch │  │                 │ │
│  │ • SSH  (2222)   │  │ • Logstash      │  │ • MaxMind API   │ │
│  │ • HTTP (8080)   │  │ • Kibana        │  │ • Threat Intel  │ │
│  │ • FTP  (2121)   │  │                 │  │                 │ │
│  │ • Telnet (2323) │  └─────────────────┘  └─────────────────┘ │
│  └─────────────────┘           │                    │          │
│           │                    │                    │          │
│           └────────────────────┼────────────────────┘          │
│                                │                               │
│  ┌─────────────────────────────┴─────────────────────────────┐ │
│  │                Alert System                               │ │
│  │  • Email Notifications  • Discord Webhooks               │ │
│  │  • Slack Integration    • Threat Categorization          │ │
│  └───────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- **Docker & Docker Compose** (v20.10+ recommended)
- **Git** for cloning the repository
- **Terraform** (v1.0+) for infrastructure deployment
- **AWS Account** (Free Tier compatible)
- **MaxMind GeoIP Account** (Free registration required)

### 🏠 Local Development Deployment

Perfect for testing, development, and learning cybersecurity concepts.

```bash
# 1. Clone the repository
git clone https://github.com/HOAX-116/honeypot-application.git
cd honeypot-application

# 2. Configure environment variables
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your credentials (see Configuration section)

# 3. Start all services locally
docker-compose up -d

# 4. Verify deployment
./scripts/monitor.sh

# 5. Access services
echo "🔍 Kibana Dashboard: http://localhost:5601"
echo "🕷️ SSH Honeypot: localhost:2222"
echo "🌐 HTTP Honeypot: http://localhost:8080"
echo "📁 FTP Honeypot: localhost:2121"
echo "📟 Telnet Honeypot: localhost:2323"
echo "🔧 API Gateway: http://localhost:8000"
```

### ☁️ AWS Production Deployment

Complete infrastructure automation with Terraform for production environments.

```bash
# 1. Configure AWS credentials
aws configure
# Or export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY

# 2. Configure deployment variables
cp terraform.tfvars.example terraform.tfvars
# Edit with your specific configuration

# 3. Deploy infrastructure
terraform init
terraform plan
terraform apply

# 4. Get deployment information
terraform output

# 5. Access your honeypot system
# Kibana: http://<instance-ip>:5601
# SSH Honeypot: <instance-ip>:2222
```

### 🚀 One-Command Deployment

Use our automated deployment script for quick setup:

```bash
# Local deployment
./scripts/deploy.sh --local

# AWS deployment
./scripts/deploy.sh --aws --region us-east-1
```

## 📋 System Components

### 🕷️ Honeypot Services

| Service | Port | Technology | Purpose | Features |
|---------|------|------------|---------|----------|
| **SSH** | 2222 | Python + Paramiko | SSH brute force attacks | Interactive shell simulation, credential logging |
| **HTTP** | 8080 | Flask + Python | Web application attacks | Fake login pages, payload capture, file upload traps |
| **FTP** | 2121 | Python FTP Server | File transfer attacks | Directory traversal, credential harvesting |
| **Telnet** | 2323 | Socket-based Python | Legacy protocol attacks | Command simulation, session logging |

### 🛠️ Supporting Services

| Service | Purpose | Technology | Features |
|---------|---------|------------|----------|
| **GeoIP Enrichment** | IP geolocation analysis | MaxMind + Python | Real-time country/city detection, ISP mapping |
| **Alert Management** | Threat notifications | Python + SMTP/Webhooks | Email, Discord, Slack alerts with threat intelligence |
| **API Gateway** | System management | Flask REST API | Honeypot control, statistics, data export |
| **Health Monitor** | System monitoring | Python + Docker API | Service health, resource monitoring, auto-recovery |

### 📊 ELK Stack Configuration

- **Elasticsearch 8.11.0**: Distributed search and analytics engine
- **Logstash 8.11.0**: Data processing pipeline with custom honeypot parsing
- **Kibana 8.11.0**: Data visualization and dashboard platform

### 🌍 GeoIP Integration

- **MaxMind GeoLite2**: Free IP geolocation database
- **Real-time enrichment**: Automatic geographic data enhancement
- **Threat intelligence**: ISP, organization, and ASN mapping
- **Custom analytics**: Attack pattern analysis by geography

## 🔧 Configuration

### 📝 Configuration Files

The system uses `terraform.tfvars` for configuration. Copy the example and customize:

```bash
cp terraform.tfvars.example terraform.tfvars
```

### 🔑 Required Configuration

Edit `terraform.tfvars` with your specific settings:

```hcl
# AWS Configuration
aws_region = "us-east-1"
project_name = "honeypot-system"
environment = "production"

# EC2 Configuration
instance_type = "t3.medium"  # or t2.micro for free tier
key_name = "your-ec2-key-pair"

# Network Configuration
vpc_cidr = "10.0.0.0/16"
subnet_cidr = "10.0.1.0/24"
allowed_ssh_cidr = "YOUR_IP/32"  # Restrict to your IP for security

# MaxMind GeoIP Configuration (Free account required)
maxmind_account_id = "your-maxmind-account-id"
maxmind_license_key = "your-maxmind-license-key"

# Email Alert Configuration
smtp_host = "smtp.gmail.com"
smtp_port = 587
smtp_user = "your-email@gmail.com"
smtp_pass = "your-app-password"

# Optional Webhook Notifications
discord_webhook_url = "https://discord.com/api/webhooks/your-webhook"
slack_webhook_url = "https://hooks.slack.com/services/your-webhook"
```

### 🌍 MaxMind GeoIP Setup

1. **Create Free Account**: Visit [MaxMind](https://www.maxmind.com/en/geolite2/signup)
2. **Generate License Key**: Go to Account → Manage License Keys
3. **Add to Configuration**: Update `terraform.tfvars` with your credentials
4. **Automatic Download**: System downloads GeoLite2 databases automatically

### 🐳 Local Development Configuration

For local development, the system uses environment variables from docker-compose:

```yaml
# docker-compose.yml environment section
environment:
  - MAXMIND_ACCOUNT_ID=${MAXMIND_ACCOUNT_ID}
  - MAXMIND_LICENSE_KEY=${MAXMIND_LICENSE_KEY}
  - SMTP_HOST=${SMTP_HOST}
  - SMTP_USER=${SMTP_USER}
  - SMTP_PASS=${SMTP_PASS}
  - LOG_LEVEL=INFO
```

Create a `.env` file for local development:

```bash
# .env file for local development
MAXMIND_ACCOUNT_ID=your_account_id
MAXMIND_LICENSE_KEY=your_license_key
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your_webhook
```

## 🐳 Docker Services

### Core Services

```yaml
services:
  # Honeypot Services
  ssh-honeypot:
    build: ./honeypots/ssh
    ports: ["2222:22"]
    
  http-honeypot:
    build: ./honeypots/http
    ports: ["8080:80"]
    
  ftp-honeypot:
    build: ./honeypots/ftp
    ports: ["2121:21"]
    
  telnet-honeypot:
    build: ./honeypots/telnet
    ports: ["2323:23"]

  # ELK Stack
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    
  logstash:
    image: docker.elastic.co/logstash/logstash:8.11.0
    
  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    ports: ["5601:5601"]

  # GeoIP Service
  geoip-enricher:
    build: ./services/geoip
    depends_on: [elasticsearch]
```

## 📊 Dashboard & Monitoring

### Kibana Dashboards

Access Kibana at `http://localhost:5601` or `http://your-aws-ip:5601`

**Pre-configured Dashboards:**

1. **Attack Overview**: Real-time attack statistics
2. **Geolocation Map**: Global attack origins
3. **Service Analysis**: Per-service attack patterns
4. **Threat Intelligence**: IOC analysis and categorization
5. **Timeline View**: Attack progression over time

### Key Metrics

- **Attack Volume**: Requests per minute/hour/day
- **Geographic Distribution**: Top attacking countries
- **Service Targeting**: Most targeted honeypot services
- **Credential Analysis**: Common username/password combinations
- **Payload Analysis**: Malware and exploit attempts

## 🚨 Alert System

### Email Alerts

Configured to send alerts for:
- High-volume attacks (>100 attempts/hour)
- New attack vectors
- Critical payload detection
- Geolocation anomalies

### Discord Integration

Real-time notifications with:
- Attack summaries
- Geographic information
- Threat severity levels
- Quick response suggestions

### Slack Integration

Professional notifications including:
- Daily/weekly reports
- Incident escalation
- Team collaboration features

## 🔐 Security Considerations

### Isolation

- All honeypots run in isolated Docker containers
- No direct access to host system
- Limited resource allocation
- Network segmentation

### Data Protection

- Encrypted log storage
- Access control for dashboards
- API key management
- Secure transmission protocols

### AWS Security

- Security groups with minimal required ports
- IAM roles with least privilege
- VPC isolation
- CloudWatch monitoring

## 💰 AWS Free Tier Optimization

### Resource Allocation

```yaml
EC2 Instance: t2.micro (1 vCPU, 1GB RAM)
Storage: 8GB EBS (Free Tier: 30GB available)
Network: Minimal data transfer
Monitoring: CloudWatch basic metrics
```

### Cost Management

- **Resource Limits**: CPU and memory limits in Docker
- **Log Rotation**: Automated cleanup of old logs
- **Data Retention**: 30-day retention policy
- **Monitoring**: Built-in cost tracking

### Performance Tuning

```bash
# Elasticsearch heap size
ES_JAVA_OPTS="-Xms256m -Xmx256m"

# Logstash heap size
LS_JAVA_OPTS="-Xms128m -Xmx128m"

# Container resource limits
deploy:
  resources:
    limits:
      memory: 512M
    reservations:
      memory: 256M
```

## 🚀 Deployment Instructions

### 🏠 Local Development Deployment

Perfect for learning, testing, and development environments.

#### Step 1: Prerequisites Installation

```bash
# Install Docker (Ubuntu/Debian)
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

#### Step 2: Clone and Setup

```bash
# 1. Clone the repository
git clone https://github.com/HOAX-116/honeypot-application.git
cd honeypot-application

# 2. Create environment file
cp terraform.tfvars.example .env

# 3. Edit environment variables (minimal setup for local)
cat > .env << EOF
MAXMIND_ACCOUNT_ID=your_account_id
MAXMIND_LICENSE_KEY=your_license_key
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
LOG_LEVEL=INFO
EOF
```

#### Step 3: System Configuration

```bash
# Increase virtual memory for Elasticsearch
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf

# Create necessary directories
mkdir -p logs data/elasticsearch data/geoip

# Set permissions
sudo chown -R 1000:1000 data/
```

#### Step 4: Deploy Services

```bash
# Build all services
docker-compose build

# Start all services in background
docker-compose up -d

# Monitor startup logs
docker-compose logs -f

# Wait for services to be ready (takes 2-3 minutes)
./scripts/monitor.sh
```

#### Step 5: Verify Deployment

```bash
# Check service status
docker-compose ps

# Test honeypot services
echo "Testing SSH honeypot..."
ssh -p 2222 admin@localhost

echo "Testing HTTP honeypot..."
curl http://localhost:8080

echo "Testing FTP honeypot..."
ftp localhost 2121

echo "Testing API gateway..."
curl http://localhost:8000/api/v1/health
```

#### Step 6: Access Dashboards

```bash
# Service URLs
echo "🔍 Kibana Dashboard: http://localhost:5601"
echo "🔧 API Gateway: http://localhost:8000"
echo "📊 Health Monitor: http://localhost:8000/api/v1/health"

# Honeypot endpoints
echo "🕷️ SSH Honeypot: localhost:2222"
echo "🌐 HTTP Honeypot: http://localhost:8080"
echo "📁 FTP Honeypot: localhost:2121"
echo "📟 Telnet Honeypot: localhost:2323"
```

### 🔧 Local Development Tips

#### Resource Management

```bash
# Monitor resource usage
docker stats

# Reduce resource usage for low-memory systems
export ES_JAVA_OPTS="-Xms256m -Xmx256m"
export LS_JAVA_OPTS="-Xms128m -Xmx128m"

# Restart with reduced memory
docker-compose down
docker-compose up -d
```

#### Development Workflow

```bash
# View real-time logs
docker-compose logs -f ssh-honeypot
docker-compose logs -f http-honeypot

# Restart specific service
docker-compose restart ssh-honeypot

# Rebuild and restart service
docker-compose up -d --build ssh-honeypot

# Access service shell for debugging
docker-compose exec ssh-honeypot /bin/bash
```

#### Data Management

```bash
# Backup honeypot data
./scripts/backup.sh --local

# Clear all data (reset system)
docker-compose down -v
sudo rm -rf data/elasticsearch/*
docker-compose up -d

# Export attack data
curl "http://localhost:8000/api/v1/export?format=json&days=7" > attacks.json
```

### AWS Production Deployment

```bash
# 1. Launch EC2 instance
aws ec2 run-instances \
  --image-id ami-0abcdef1234567890 \
  --instance-type t2.micro \
  --key-name your-key-pair \
  --security-group-ids sg-12345678 \
  --user-data file://scripts/user-data.sh

# 2. SSH to instance
ssh -i your-key.pem ec2-user@your-instance-ip

# 3. Clone and deploy
git clone https://github.com/your-username/honeypot-system.git
cd honeypot-system
./scripts/aws-setup.sh

# 4. Configure environment
sudo cp .env.example .env
sudo nano .env  # Add your credentials

# 5. Deploy system
sudo docker-compose up -d

# 6. Configure security groups
# Open ports: 22 (SSH), 5601 (Kibana), 2222 (SSH Honeypot), 8080 (HTTP Honeypot)
```

### Terraform Deployment

```bash
cd terraform/

# Initialize Terraform
terraform init

# Review planned changes
terraform plan -var="maxmind_license_key=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"

# Deploy infrastructure
terraform apply -auto-approve

# Get instance IP
terraform output instance_ip
```

## 📈 Usage Examples

### Monitoring Attacks

```bash
# View real-time logs
docker-compose logs -f ssh-honeypot

# Check attack statistics
curl -X GET "localhost:9200/honeypot-logs/_search?pretty"

# Generate daily report
./scripts/generate-report.sh --date=today
```

### Custom Alerts

```python
# Add custom alert rules
python scripts/add_alert_rule.py \
  --service=ssh \
  --threshold=50 \
  --window=1h \
  --action=email
```

### Data Export

```bash
# Export attack data
./scripts/export-data.sh \
  --format=csv \
  --service=all \
  --date-range="2025-01-01,2025-01-31"
```

## 🔧 Troubleshooting

### 🏠 Local Deployment Issues

#### Elasticsearch Issues

**Issue**: Elasticsearch won't start or crashes
```bash
# Solution 1: Increase virtual memory
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf

# Solution 2: Check disk space
df -h
# Ensure at least 2GB free space

# Solution 3: Reduce memory usage
export ES_JAVA_OPTS="-Xms256m -Xmx256m"
docker-compose down && docker-compose up -d elasticsearch
```

**Issue**: Elasticsearch "yellow" cluster health
```bash
# This is normal for single-node development
# Check status
curl http://localhost:9200/_cluster/health?pretty

# Force green status (development only)
curl -X PUT "localhost:9200/_settings" -H 'Content-Type: application/json' -d'
{
  "index": {
    "number_of_replicas": 0
  }
}'
```

#### Docker Issues

**Issue**: Permission denied errors
```bash
# Solution: Fix Docker permissions
sudo usermod -aG docker $USER
newgrp docker

# Fix data directory permissions
sudo chown -R 1000:1000 data/
sudo chmod -R 755 data/
```

**Issue**: Port conflicts
```bash
# Check what's using ports
sudo netstat -tulpn | grep :5601
sudo netstat -tulpn | grep :9200

# Kill conflicting processes
sudo fuser -k 5601/tcp
sudo fuser -k 9200/tcp

# Or change ports in docker-compose.yml
```

#### Memory Issues

**Issue**: System running out of memory
```bash
# Check memory usage
free -h
docker stats

# Reduce resource allocation
cat > docker-compose.override.yml << EOF
version: '3.8'
services:
  elasticsearch:
    environment:
      - "ES_JAVA_OPTS=-Xms256m -Xmx256m"
  logstash:
    environment:
      - "LS_JAVA_OPTS=-Xms128m -Xmx128m"
EOF

# Restart services
docker-compose down && docker-compose up -d
```

#### Service Connection Issues

**Issue**: Services can't connect to Elasticsearch
```bash
# Check Elasticsearch is running
curl http://localhost:9200/_cluster/health

# Check Docker network
docker network ls
docker network inspect honeypot-application_default

# Restart dependent services
docker-compose restart logstash kibana geoip-service
```

#### MaxMind GeoIP Issues

**Issue**: GeoIP service fails to download databases
```bash
# Verify credentials
curl -u "YOUR_ACCOUNT_ID:YOUR_LICENSE_KEY" \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz"

# Check service logs
docker-compose logs geoip-service

# Manual database download
mkdir -p data/geoip
cd data/geoip
wget "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_LICENSE_KEY&suffix=tar.gz" -O GeoLite2-City.tar.gz
```

### 🔍 Health Checks and Monitoring

#### System Health Commands

```bash
# Overall system health
./scripts/monitor.sh

# Individual service health
docker-compose ps
docker-compose logs --tail=50 SERVICE_NAME

# Resource monitoring
docker stats --no-stream
df -h
free -h

# Network connectivity
docker-compose exec ssh-honeypot ping elasticsearch
docker-compose exec api-gateway curl http://elasticsearch:9200/_cluster/health
```

#### Service-Specific Checks

```bash
# Elasticsearch health
curl "http://localhost:9200/_cluster/health?pretty"
curl "http://localhost:9200/_cat/indices?v"

# Kibana health
curl "http://localhost:5601/api/status"

# Logstash health
curl "http://localhost:9600/_node/stats?pretty"

# API Gateway health
curl "http://localhost:8000/api/v1/health"

# Test honeypot services
ssh -p 2222 test@localhost  # Should connect and log attempt
curl http://localhost:8080  # Should return honeypot page
```

#### Log Analysis

```bash
# View all service logs
docker-compose logs

# Follow specific service logs
docker-compose logs -f elasticsearch
docker-compose logs -f ssh-honeypot

# Search for errors
docker-compose logs | grep -i error
docker-compose logs | grep -i exception

# Export logs for analysis
docker-compose logs > system_logs.txt
```

### 🚨 Emergency Recovery

#### Complete System Reset

```bash
# Stop all services
docker-compose down

# Remove all data (WARNING: This deletes all honeypot data)
sudo rm -rf data/
docker volume prune -f

# Recreate directories
mkdir -p logs data/elasticsearch data/geoip
sudo chown -R 1000:1000 data/

# Restart system
docker-compose up -d
```

#### Partial Recovery

```bash
# Reset only Elasticsearch data
docker-compose stop elasticsearch kibana logstash
sudo rm -rf data/elasticsearch/*
docker-compose start elasticsearch

# Wait for Elasticsearch to be ready
sleep 30

# Restart dependent services
docker-compose start kibana logstash
```

### 📞 Getting Help

If you encounter issues not covered here:

1. **Check logs**: `docker-compose logs SERVICE_NAME`
2. **Verify configuration**: Ensure `.env` file has correct values
3. **Check resources**: Ensure sufficient memory and disk space
4. **Review documentation**: See `DEPLOYMENT.md` for detailed instructions
5. **Create issue**: [GitHub Issues](https://github.com/HOAX-116/honeypot-application/issues)

## 📚 API Documentation

### REST Endpoints

```bash
# Get attack statistics
GET /api/v1/stats
Response: {
  "total_attacks": 1234,
  "attacks_by_service": {...},
  "top_countries": [...],
  "recent_attacks": [...]
}

# Get geolocation data
GET /api/v1/geoip/{ip_address}
Response: {
  "ip": "192.168.1.1",
  "country": "US",
  "city": "New York",
  "isp": "Example ISP"
}

# Export data
POST /api/v1/export
Body: {
  "format": "json|csv",
  "date_range": "2025-01-01,2025-01-31",
  "services": ["ssh", "http"]
}
```

### WebSocket Events

```javascript
// Real-time attack feed
ws://localhost:8765/attacks

// Event format
{
  "timestamp": "2025-01-15T10:30:00Z",
  "service": "ssh",
  "source_ip": "192.168.1.100",
  "country": "CN",
  "attack_type": "brute_force",
  "credentials": {"username": "admin", "password": "123456"}
}
```

## 🤝 Contributing

### Development Setup

```bash
# Fork and clone
git clone https://github.com/your-username/honeypot-system.git
cd honeypot-system

# Create development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt

# Run tests
pytest tests/
```

### Adding New Honeypots

1. Create honeypot directory: `honeypots/new-service/`
2. Implement service logic
3. Add Docker configuration
4. Update docker-compose.yml
5. Add Logstash parsing rules
6. Create Kibana visualizations

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 📞 Support

- **Documentation**: [Wiki](https://github.com/your-username/honeypot-system/wiki)
- **Issues**: [GitHub Issues](https://github.com/your-username/honeypot-system/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/honeypot-system/discussions)

## 🙏 Acknowledgments

- MaxMind for GeoIP data
- Elastic Stack for logging infrastructure
- Docker community for containerization
- AWS for cloud infrastructure
- Cybersecurity research community

---

**⚠️ Disclaimer**: This honeypot system is designed for educational and research purposes. Deploy responsibly and in accordance with your organization's security policies and legal requirements.
