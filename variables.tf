# =============================================================================
# Terraform Variables for Honeypot System
# File: terraform/variables.tf
# =============================================================================

# Project Configuration
variable "project_name" {
  description = "Name of the honeypot project"
  type        = string
  default     = "honeypot-system"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "owner" {
  description = "Owner of the infrastructure"
  type        = string
  default     = "cybersec-team"
}

# AWS Configuration
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type (free tier: t2.micro)"
  type        = string
  default     = "t2.micro"

  validation {
    condition     = contains(["t2.micro", "t2.small", "t2.medium", "t3.micro", "t3.small"], var.instance_type)
    error_message = "Instance type must be compatible with free tier or cost-effective options."
  }
}

variable "root_volume_size" {
  description = "Root volume size in GB (free tier: up to 30GB)"
  type        = number
  default     = 20

  validation {
    condition     = var.root_volume_size >= 8 && var.root_volume_size <= 30
    error_message = "Root volume size must be between 8GB and 30GB for free tier compatibility."
  }
}

# Network Configuration
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

# Security Configuration
variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Restrict this in production
}

variable "allowed_dashboard_cidrs" {
  description = "CIDR blocks allowed for dashboard access"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Restrict this in production
}

variable "allowed_api_cidrs" {
  description = "CIDR blocks allowed for API access"
  type        = list(string)
  default     = ["0.0.0.0/0"] # Restrict this in production
}

# Key Pair Configuration
variable "public_key" {
  description = "Public key for EC2 access"
  type        = string
  sensitive   = true
}

variable "private_key_path" {
  description = "Path to private key file"
  type        = string
  default     = "~/.ssh/id_rsa"
}

# MaxMind Configuration
variable "maxmind_account_id" {
  description = "MaxMind account ID for GeoIP"
  type        = string
  default     = "1177216"
  sensitive   = true
}

variable "maxmind_license_key" {
  description = "MaxMind license key for GeoIP"
  type        = string
  default     = "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"
  sensitive   = true
}

# Email Configuration
variable "smtp_host" {
  description = "SMTP host for email alerts"
  type        = string
  default     = "smtp.gmail.com"
}

variable "smtp_user" {
  description = "SMTP username for email alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "smtp_pass" {
  description = "SMTP password for email alerts"
  type        = string
  default     = ""
  sensitive   = true
}

# Webhook Configuration
variable "discord_webhook_url" {
  description = "Discord webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

# Backup Configuration
variable "backup_retention_days" {
  description = "Number of days to retain backup files"
  type        = number
  default     = 30

  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 365
    error_message = "Backup retention must be between 7 and 365 days."
  }
}

variable "log_retention_days" {
  description = "Number of days to retain CloudWatch logs"
  type        = number
  default     = 14

  validation {
    condition     = var.log_retention_days >= 1 && var.log_retention_days <= 365
    error_message = "Log retention must be between 1 and 365 days."
  }
}

# Monitoring Configuration
variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring (additional cost)"
  type        = bool
  default     = false
}

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for system monitoring"
  type        = bool
  default     = true
}

# Honeypot Configuration
variable "honeypot_services" {
  description = "List of honeypot services to deploy"
  type        = list(string)
  default     = ["ssh", "http", "ftp", "telnet"]

  validation {
    condition = alltrue([
      for service in var.honeypot_services : contains(["ssh", "http", "ftp", "telnet"], service)
    ])
    error_message = "Honeypot services must be one of: ssh, http, ftp, telnet."
  }
}

variable "log_level" {
  description = "Log level for honeypot services"
  type        = string
  default     = "INFO"

  validation {
    condition     = contains(["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], var.log_level)
    error_message = "Log level must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL."
  }
}

# Resource Limits
variable "elasticsearch_heap_size" {
  description = "Elasticsearch heap size (e.g., 256m, 512m)"
  type        = string
  default     = "256m"
}

variable "logstash_heap_size" {
  description = "Logstash heap size (e.g., 128m, 256m)"
  type        = string
  default     = "128m"
}

# Alert Thresholds
variable "high_volume_threshold" {
  description = "Threshold for high-volume attack alerts (attacks per hour)"
  type        = number
  default     = 100
}

variable "critical_threat_threshold" {
  description = "Threshold for critical threat alerts (reputation score)"
  type        = number
  default     = 50
}

# Data Retention
variable "elasticsearch_retention_days" {
  description = "Number of days to retain data in Elasticsearch"
  type        = number
  default     = 30
}

# Cost Optimization
variable "enable_spot_instances" {
  description = "Use spot instances for cost optimization (not recommended for production)"
  type        = bool
  default     = false
}

variable "auto_shutdown_schedule" {
  description = "Cron expression for automatic shutdown (empty to disable)"
  type        = string
  default     = ""
}

# Tagging
variable "additional_tags" {
  description = "Additional tags to apply to all resources"
  type        = map(string)
  default     = {}
}
  