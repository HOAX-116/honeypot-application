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
  default     = ["0.0.0.0/0"]  # Restrict this in production
}

variable "allowed_dashboard_cidrs" {
  description = "CIDR blocks allowed for dashboard access"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Restrict this in production
}

variable "allowed_api_cidrs" {
  description = "CIDR blocks allowed for API access"
  type        = list(string)
  default     = ["0.0.0.0/0"]  # Restrict this in production
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
  