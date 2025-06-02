# Multi-Service Cybersecurity Honeypot System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![AWS Free Tier](https://img.shields.io/badge/AWS-Free%20Tier%20Compatible-orange.svg)](https://aws.amazon.com/free/)
[![Docker](https://img.shields.io/badge/Docker-Compose%20Ready-blue.svg)](https://docs.docker.com/compose/)

A comprehensive, production-ready honeypot system designed for cybersecurity research and learning. Deploy multiple service honeypots, capture attacker behavior, perform geolocation analysis, and visualize threats in real-time.

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

- Docker & Docker Compose
- AWS Account (Free Tier)
- MaxMind GeoIP Account (Free)
- Git

### 1-Click Local Deployment

```bash
# Clone the repository
git clone https://github.com/your-username/honeypot-system.git
cd honeypot-system

# Set up environment variables
cp .env.example .env
# Edit .env with your MaxMind credentials

# Deploy the entire system
docker-compose up -d

# Access Kibana Dashboard
open http://localhost:5601
```

### AWS Free Tier Deployment

```bash
# Launch EC2 instance (t2.micro)
./scripts/aws-deploy.sh

# Or use Terraform
cd terraform/
terraform init
terraform plan
terraform apply
```

## 📋 System Components

### Honeypot Services

| Service | Port | Purpose | Logging |
|---------|------|---------|---------|
| SSH | 2222 | Capture SSH brute force attacks | ✅ |
| HTTP | 8080 | Web application attacks | ✅ |
| FTP | 2121 | File transfer protocol attacks | ✅ |
| Telnet | 2323 | Legacy protocol attacks | ✅ |

### ELK Stack Configuration

- **Elasticsearch**: Data storage and indexing
- **Logstash**: Log processing and enrichment
- **Kibana**: Visualization and dashboards

### GeoIP Integration

- **MaxMind GeoLite2**: IP geolocation database
- **Real-time analysis**: Automatic country/city detection
- **Threat intelligence**: ISP and organization mapping

## 🔧 Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# MaxMind GeoIP Configuration
MAXMIND_ACCOUNT_ID=1177216
MAXMIND_LICENSE_KEY=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

# Elasticsearch Configuration
ELASTIC_PASSWORD=your_secure_password
ELASTIC_USERNAME=elastic

# Alert Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password

# Discord Webhook (Optional)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook

# Slack Webhook (Optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/your_webhook

# System Configuration
LOG_LEVEL=INFO
HONEYPOT_NETWORK=honeypot_net
```

### MaxMind API Setup

1. **Account Setup**: Your credentials are already provided
   - Account ID: `1177216`
   - License Key: `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`

2. **Database Download**: The system automatically downloads GeoLite2 databases

3. **API Integration**: Configured in `config/geoip-config.yml`

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

### Local Development

```bash
# 1. Clone and setup
git clone https://github.com/your-username/honeypot-system.git
cd honeypot-system

# 2. Configure environment
cp .env.example .env
# Edit .env with your credentials

# 3. Build and deploy
docker-compose build
docker-compose up -d

# 4. Verify deployment
./scripts/health-check.sh

# 5. Access services
echo "Kibana: http://localhost:5601"
echo "SSH Honeypot: localhost:2222"
echo "HTTP Honeypot: http://localhost:8080"
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

### Common Issues

**Issue**: Elasticsearch won't start
```bash
# Solution: Increase virtual memory
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf
```

**Issue**: High memory usage
```bash
# Solution: Reduce heap sizes
export ES_JAVA_OPTS="-Xms128m -Xmx128m"
export LS_JAVA_OPTS="-Xms64m -Xmx64m"
```

**Issue**: MaxMind API errors
```bash
# Solution: Verify credentials
curl -u "1177216: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" \
  "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=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&suffix=tar.gz"
```

### Health Checks

```bash
# System health
./scripts/health-check.sh

# Service status
docker-compose ps

# Resource usage
docker stats

# Log analysis
./scripts/analyze-logs.sh --service=all --last=1h
```

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
