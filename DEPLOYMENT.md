# Honeypot Deployment Guide

This guide provides step-by-step instructions for deploying the multi-service cybersecurity honeypot system.

## Prerequisites

### Required Tools
- **Terraform** (>= 1.0)
- **AWS CLI** (>= 2.0)
- **Docker** (>= 20.0)
- **Docker Compose** (>= 2.0)
- **jq** (for JSON processing)
- **SSH client**

### AWS Requirements
- AWS account with appropriate permissions
- AWS CLI configured with credentials
- EC2 key pair (will be created automatically)

## Quick Start

### 1. Clone and Setup
```bash
git clone <repository-url>
cd honeypot-application
```

### 2. Configure Variables
```bash
# Copy the example configuration
cp templates/terraform.tfvars.example terraform.tfvars

# Edit with your specific values
nano terraform.tfvars
```

**Important**: Update the following in `terraform.tfvars`:
- `aws_region` - Your preferred AWS region
- `availability_zones` - AZs in your region
- `allowed_management_ips` - Your public IP address
- Email/Slack configuration for alerts

### 3. Deploy Infrastructure
```bash
# Make deployment script executable
chmod +x scripts/deploy.sh

# Run deployment
./scripts/deploy.sh deploy
```

The deployment script will:
- Check prerequisites
- Generate SSH keys
- Initialize Terraform
- Plan and apply infrastructure
- Wait for services to start
- Run health checks
- Display access information

### 4. Access Services

After deployment, you'll have access to:

- **Kibana Dashboard**: `http://<public-ip>:5601`
- **API Gateway**: `http://<public-ip>:8080`
- **Elasticsearch**: `http://<public-ip>:9200`
- **SSH Management**: `ssh -i keys/honeypot-key.pem ec2-user@<public-ip>`

## Manual Deployment

If you prefer manual deployment:

### 1. Initialize Terraform
```bash
terraform init
```

### 2. Plan Deployment
```bash
terraform plan
```

### 3. Apply Infrastructure
```bash
terraform apply
```

### 4. Get Outputs
```bash
terraform output
```

## Configuration Details

### Terraform Variables

Key variables in `terraform.tfvars`:

```hcl
# AWS Configuration
aws_region = "us-east-1"
availability_zones = ["us-east-1a", "us-east-1b"]

# Instance Configuration
instance_type = "t3.medium"
root_volume_size = 50
data_volume_size = 100

# Network Configuration
vpc_cidr = "10.0.0.0/16"
allowed_management_ips = ["YOUR.IP.ADDRESS/32"]

# Honeypot Configuration
honeypot_config = {
  ssh_port = 22
  http_port = 80
  ftp_port = 21
  telnet_port = 23
  enable_geoip = true
  enable_threat_intel = true
}

# Alert Configuration
alert_thresholds = {
  high_volume_attacks = 100
  unique_ips_per_hour = 50
  brute_force_attempts = 20
}
```

### Environment Variables

Set these environment variables for enhanced functionality:

```bash
# Email Alerts
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"
export ALERT_EMAIL="alerts@yourcompany.com"

# Slack Alerts
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"

# MaxMind GeoIP (optional)
export MAXMIND_ACCOUNT_ID="your-account-id"
export MAXMIND_LICENSE_KEY="your-license-key"
```

## Post-Deployment

### 1. Verify Services
```bash
# Check service status
./scripts/monitor.sh status

# View real-time monitoring
./scripts/monitor.sh monitor

# Check Elasticsearch health
./scripts/monitor.sh elasticsearch
```

### 2. Configure Alerts
```bash
# Test email alerts
curl -X POST http://<public-ip>:8080/api/test/email

# Test Slack alerts
curl -X POST http://<public-ip>:8080/api/test/slack
```

### 3. Setup Monitoring Dashboard
1. Access Kibana at `http://<public-ip>:5601`
2. Go to "Stack Management" > "Index Patterns"
3. Create index pattern: `honeypot-logs-*`
4. Set time field: `@timestamp`
5. Import pre-built dashboards from `/config/kibana/`

### 4. Configure Backups
```bash
# Create initial backup
./scripts/backup.sh backup

# Schedule daily backups (add to crontab)
0 2 * * * /opt/honeypot/scripts/backup.sh backup
```

## Monitoring and Management

### Real-time Monitoring
```bash
# Real-time dashboard
./scripts/monitor.sh monitor

# View recent attacks
./scripts/monitor.sh stats

# Check system resources
./scripts/monitor.sh resources
```

### Log Analysis
```bash
# View recent logs
./scripts/monitor.sh logs 50

# Search specific service logs
./scripts/monitor.sh docker-logs ssh-honeypot 100

# Generate security report
./scripts/monitor.sh report 24
```

### Service Management
```bash
# Restart all services
./scripts/monitor.sh restart

# Restart specific service
./scripts/monitor.sh restart elasticsearch

# View service status
./scripts/monitor.sh status
```

## Backup and Recovery

### Create Backup
```bash
# Manual backup
./scripts/backup.sh backup

# List available backups
./scripts/backup.sh list
```

### Restore from Backup
```bash
# Restore specific backup
./scripts/backup.sh restore honeypot_backup_20240602_120000
```

## Security Considerations

### Network Security
- Only management IPs can access port 2222 (SSH)
- Honeypot ports (22, 80, 21, 23) are open to all
- Management ports (5601, 8080, 9200) restricted to management IPs

### Data Protection
- All data encrypted in transit and at rest
- Regular automated backups to S3
- Log retention policies configured
- Access logging enabled

### Monitoring
- Real-time attack detection
- Automated alerting for high-volume attacks
- GeoIP enrichment for threat intelligence
- Health monitoring for all services

## Troubleshooting

### Common Issues

#### Services Not Starting
```bash
# Check Docker status
sudo systemctl status docker

# View service logs
./scripts/monitor.sh docker-logs

# Restart services
./scripts/monitor.sh restart
```

#### Elasticsearch Issues
```bash
# Check Elasticsearch health
curl http://localhost:9200/_cluster/health

# View Elasticsearch logs
./scripts/monitor.sh docker-logs elasticsearch

# Check disk space
df -h
```

#### Network Connectivity
```bash
# Check port accessibility
netstat -tlnp | grep -E ':(22|80|21|23|5601|8080|9200)'

# Test from external host
nc -zv <public-ip> 22
```

### Log Locations
- **Application logs**: `/var/log/honeypot/`
- **Docker logs**: `docker-compose logs`
- **System logs**: `/var/log/syslog`
- **Elasticsearch logs**: Container logs via Docker

### Performance Tuning

#### Elasticsearch
```bash
# Increase heap size for large deployments
export ES_JAVA_OPTS="-Xms2g -Xmx2g"
```

#### System Resources
```bash
# Monitor resource usage
./scripts/monitor.sh resources

# Check for memory issues
free -h
top
```

## Scaling

### Vertical Scaling
- Increase instance type in `terraform.tfvars`
- Adjust memory limits in `docker-compose.yml`
- Update Elasticsearch heap size

### Horizontal Scaling
- Deploy multiple honeypot instances
- Use load balancer for management interfaces
- Centralize logging to single Elasticsearch cluster

## Maintenance

### Regular Tasks
1. **Daily**: Check service health and recent attacks
2. **Weekly**: Review security reports and update threat intelligence
3. **Monthly**: Update Docker images and system packages
4. **Quarterly**: Review and update security configurations

### Updates
```bash
# Update Docker images
docker-compose pull
docker-compose up -d

# Update system packages
sudo apt update && sudo apt upgrade

# Update Terraform modules
terraform init -upgrade
```

## Cost Optimization

### Estimated Monthly Costs (USD)
- **EC2 Instance (t3.medium)**: $30-40
- **EBS Storage (150GB)**: $15-20
- **S3 Storage**: $5-10
- **Data Transfer**: $5-15
- **CloudWatch**: $2-5
- **Total**: ~$57-90/month

### Cost Reduction Tips
1. Use smaller instance types for testing
2. Enable S3 lifecycle policies for old backups
3. Optimize log retention periods
4. Use spot instances for non-production

## Support

### Getting Help
1. Check this documentation
2. Review logs and monitoring data
3. Check GitHub issues
4. Contact the security team

### Reporting Issues
When reporting issues, include:
- Error messages and logs
- System configuration
- Steps to reproduce
- Expected vs actual behavior

## Security Contacts

For security-related issues:
- **Email**: security@yourcompany.com
- **Slack**: #security-team
- **Emergency**: Follow incident response procedures