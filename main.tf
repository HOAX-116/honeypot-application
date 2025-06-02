# =============================================================================
# Multi-Service Cybersecurity Honeypot System - AWS Terraform Configuration
# File: terraform/main.tf
# =============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Honeypot-System"
      Environment = var.environment
      Owner       = var.owner
      Purpose     = "Cybersecurity-Research"
      CreatedBy   = "Terraform"
      CreatedAt   = timestamp()
    }
  }
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  
  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
  
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Create VPC
resource "aws_vpc" "honeypot_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Create Internet Gateway
resource "aws_internet_gateway" "honeypot_igw" {
  vpc_id = aws_vpc.honeypot_vpc.id
  
  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Create Public Subnet
resource "aws_subnet" "honeypot_public_subnet" {
  vpc_id                  = aws_vpc.honeypot_vpc.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  
  tags = {
    Name = "${var.project_name}-public-subnet"
    Type = "Public"
  }
}

# Create Route Table
resource "aws_route_table" "honeypot_public_rt" {
  vpc_id = aws_vpc.honeypot_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.honeypot_igw.id
  }
  
  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

# Associate Route Table with Subnet
resource "aws_route_table_association" "honeypot_public_rta" {
  subnet_id      = aws_subnet.honeypot_public_subnet.id
  route_table_id = aws_route_table.honeypot_public_rt.id
}

# Create Security Group
resource "aws_security_group" "honeypot_sg" {
  name_prefix = "${var.project_name}-sg"
  vpc_id      = aws_vpc.honeypot_vpc.id
  description = "Security group for honeypot system"
  
  # SSH access (for management)
  ingress {
    description = "SSH Management"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
  }
  
  # Kibana Dashboard
  ingress {
    description = "Kibana Dashboard"
    from_port   = 5601
    to_port     = 5601
    protocol    = "tcp"
    cidr_blocks = var.allowed_dashboard_cidrs
  }
  
  # API Gateway
  ingress {
    description = "API Gateway"
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = var.allowed_api_cidrs
  }
  
  # SSH Honeypot
  ingress {
    description = "SSH Honeypot"
    from_port   = 2222
    to_port     = 2222
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to world for honeypot
  }
  
  # HTTP Honeypot
  ingress {
    description = "HTTP Honeypot"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to world for honeypot
  }
  
  # FTP Honeypot
  ingress {
    description = "FTP Honeypot"
    from_port   = 2121
    to_port     = 2121
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to world for honeypot
  }
  
  # FTP Passive Mode
  ingress {
    description = "FTP Passive Mode"
    from_port   = 21000
    to_port     = 21010
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to world for honeypot
  }
  
  # Telnet Honeypot
  ingress {
    description = "Telnet Honeypot"
    from_port   = 2323
    to_port     = 2323
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to world for honeypot
  }
  
  # Outbound internet access
  egress {
    description = "All Outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.project_name}-security-group"
  }
}

# Create Key Pair
resource "aws_key_pair" "honeypot_key" {
  key_name   = "${var.project_name}-key"
  public_key = var.public_key
  
  tags = {
    Name = "${var.project_name}-keypair"
  }
}

# Create IAM Role for EC2
resource "aws_iam_role" "honeypot_role" {
  name = "${var.project_name}-ec2-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = {
    Name = "${var.project_name}-iam-role"
  }
}

# Create IAM Policy for CloudWatch and S3
resource "aws_iam_policy" "honeypot_policy" {
  name        = "${var.project_name}-policy"
  description = "Policy for honeypot system"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = [
          aws_s3_bucket.honeypot_backup.arn,
          "${aws_s3_bucket.honeypot_backup.arn}/*"
        ]
      }
    ]
  })
}

# Attach Policy to Role
resource "aws_iam_role_policy_attachment" "honeypot_policy_attachment" {
  policy_arn = aws_iam_policy.honeypot_policy.arn
  role       = aws_iam_role.honeypot_role.name
}

# Create Instance Profile
resource "aws_iam_instance_profile" "honeypot_profile" {
  name = "${var.project_name}-instance-profile"
  role = aws_iam_role.honeypot_role.name
}

# Create S3 Bucket for Backups
resource "aws_s3_bucket" "honeypot_backup" {
  bucket = "${var.project_name}-backups-${random_string.bucket_suffix.result}"
  
  tags = {
    Name        = "${var.project_name}-backup-bucket"
    Purpose     = "Log and Config Backups"
    Environment = var.environment
  }
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
  upper   = false
}

# Configure S3 Bucket Versioning
resource "aws_s3_bucket_versioning" "honeypot_backup_versioning" {
  bucket = aws_s3_bucket.honeypot_backup.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Configure S3 Bucket Lifecycle
resource "aws_s3_bucket_lifecycle_configuration" "honeypot_backup_lifecycle" {
  bucket = aws_s3_bucket.honeypot_backup.id
  
  rule {
    id     = "delete_old_backups"
    status = "Enabled"
    
    expiration {
      days = var.backup_retention_days
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }
}

# User Data Script
locals {
  user_data = base64encode(templatefile("${path.module}/user-data.sh", {
    maxmind_account_id  = var.maxmind_account_id
    maxmind_license_key = var.maxmind_license_key
    smtp_host          = var.smtp_host
    smtp_user          = var.smtp_user
    smtp_pass          = var.smtp_pass
    discord_webhook    = var.discord_webhook_url
    slack_webhook      = var.slack_webhook_url
    s3_backup_bucket   = aws_s3_bucket.honeypot_backup.bucket
    aws_region         = var.aws_region
  }))
}

# Launch EC2 Instance
resource "aws_instance" "honeypot_server" {
  ami                     = data.aws_ami.amazon_linux.id
  instance_type           = var.instance_type
  key_name               = aws_key_pair.honeypot_key.key_name
  vpc_security_group_ids = [aws_security_group.honeypot_sg.id]
  subnet_id              = aws_subnet.honeypot_public_subnet.id
  iam_instance_profile   = aws_iam_instance_profile.honeypot_profile.name
  
  user_data = local.user_data
  
  root_block_device {
    volume_type = "gp2"
    volume_size = var.root_volume_size
    encrypted   = true
    
    tags = {
      Name = "${var.project_name}-root-volume"
    }
  }
  
  # Enable detailed monitoring (free tier includes basic monitoring)
  monitoring = false
  
  tags = {
    Name        = "${var.project_name}-server"
    Purpose     = "Honeypot System"
    Environment = var.environment
  }
  
  # Add provisioner to wait for system to be ready
  provisioner "remote-exec" {
    inline = [
      "while [ ! -f /tmp/honeypot-setup-complete ]; do sleep 10; done",
      "echo 'Honeypot system setup completed successfully'"
    ]
    
    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = file(var.private_key_path)
      host        = self.public_ip
      timeout     = "10m"
    }
  }
}

# Create CloudWatch Log Group
resource "aws_cloudwatch_log_group" "honeypot_logs" {
  name              = "/aws/ec2/${var.project_name}"
  retention_in_days = var.log_retention_days
  
  tags = {
    Name        = "${var.project_name}-cloudwatch-logs"
    Environment = var.environment
  }
}

# Create CloudWatch Dashboard
resource "aws_cloudwatch_dashboard" "honeypot_dashboard" {
  dashboard_name = "${var.project_name}-monitoring"
  
  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        
        properties = {
          metrics = [
            ["AWS/EC2", "CPUUtilization", "InstanceId", aws_instance.honeypot_server.id],
            [".", "NetworkIn", ".", "."],
            [".", "NetworkOut", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "EC2 Instance Metrics"
          period  = 300
        }
      }
    ]
  })
}

# Outputs
output "instance_public_ip" {
  description = "Public IP address of the honeypot server"
  value       = aws_instance.honeypot_server.public_ip
}

output "instance_public_dns" {
  description = "Public DNS name of the honeypot server"
  value       = aws_instance.honeypot_server.public_dns
}

output "kibana_url" {
  description = "URL to access Kibana dashboard"
  value       = "http://${aws_instance.honeypot_server.public_ip}:5601"
}

output "api_url" {
  description = "URL to access API gateway"
  value       = "http://${aws_instance.honeypot_server.public_ip}:8000"
}

output "ssh_connection_command" {
  description = "SSH command to connect to the instance"
  value       = "ssh -i ${var.private_key_path} ec2-user@${aws_instance.honeypot_server.public_ip}"
}

output "honeypot_endpoints" {
  description = "Honeypot service endpoints"
  value = {
    ssh    = "${aws_instance.honeypot_server.public_ip}:2222"
    http   = "http://${aws_instance.honeypot_server.public_ip}:8080"
    ftp    = "${aws_instance.honeypot_server.public_ip}:2121"
    telnet = "${aws_instance.honeypot_server.public_ip}:2323"
  }
}

output "s3_backup_bucket" {
  description = "S3 bucket for backups"
  value       = aws_s3_bucket.honeypot_backup.bucket
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.honeypot_logs.name
}