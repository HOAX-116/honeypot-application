# Instance Outputs
output "instance_id" {
  description = "ID of the honeypot EC2 instance"
  value       = aws_instance.honeypot_server.id
}

output "instance_public_ip" {
  description = "Public IP address of the honeypot instance"
  value       = aws_instance.honeypot_server.public_ip
}

output "instance_private_ip" {
  description = "Private IP address of the honeypot instance"
  value       = aws_instance.honeypot_server.private_ip
}

output "instance_public_dns" {
  description = "Public DNS name of the honeypot instance"
  value       = aws_instance.honeypot_server.public_dns
}

# Network Outputs
output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.honeypot_vpc.id
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.honeypot_vpc.cidr_block
}

output "public_subnet_id" {
  description = "ID of the public subnet"
  value       = aws_subnet.honeypot_public_subnet.id
}

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.honeypot_igw.id
}

# Security Group Outputs
output "honeypot_security_group_id" {
  description = "ID of the honeypot security group"
  value       = aws_security_group.honeypot_sg.id
}

# S3 Outputs
output "backup_bucket_name" {
  description = "Name of the S3 backup bucket"
  value       = aws_s3_bucket.honeypot_backup.bucket
}

output "backup_bucket_arn" {
  description = "ARN of the S3 backup bucket"
  value       = aws_s3_bucket.honeypot_backup.arn
}

# CloudWatch Outputs
output "cloudwatch_log_group" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.honeypot_logs.name
}

output "cloudwatch_log_group_arn" {
  description = "CloudWatch log group ARN"
  value       = aws_cloudwatch_log_group.honeypot_logs.arn
}

# IAM Outputs
output "instance_role_arn" {
  description = "ARN of the instance IAM role"
  value       = aws_iam_role.honeypot_role.arn
}

output "instance_profile_name" {
  description = "Name of the instance profile"
  value       = aws_iam_instance_profile.honeypot_profile.name
}

# Service URLs
output "kibana_url" {
  description = "URL to access Kibana dashboard"
  value       = "http://${aws_instance.honeypot_server.public_ip}:5601"
}

output "elasticsearch_url" {
  description = "URL to access Elasticsearch"
  value       = "http://${aws_instance.honeypot_server.public_ip}:9200"
}

output "api_gateway_url" {
  description = "URL to access API gateway"
  value       = "http://${aws_instance.honeypot_server.public_ip}:8000"
}

# SSH Connection
output "ssh_connection_command" {
  description = "SSH command to connect to the instance"
  value       = "ssh -i ${var.private_key_path} ec2-user@${aws_instance.honeypot_server.public_ip}"
}

# Honeypot Service Endpoints
output "honeypot_endpoints" {
  description = "Honeypot service endpoints"
  value = {
    ssh    = "${aws_instance.honeypot_server.public_ip}:2222"
    http   = "http://${aws_instance.honeypot_server.public_ip}:8080"
    ftp    = "${aws_instance.honeypot_server.public_ip}:2121"
    telnet = "${aws_instance.honeypot_server.public_ip}:2323"
  }
}

# Management Information
output "management_info" {
  description = "Management and monitoring information"
  value = {
    kibana_dashboard = "http://${aws_instance.honeypot_server.public_ip}:5601"
    api_gateway      = "http://${aws_instance.honeypot_server.public_ip}:8000"
    elasticsearch    = "http://${aws_instance.honeypot_server.public_ip}:9200"
    ssh_command      = "ssh -i ${var.private_key_path} ec2-user@${aws_instance.honeypot_server.public_ip}"
    backup_bucket    = aws_s3_bucket.honeypot_backup.bucket
    log_group        = aws_cloudwatch_log_group.honeypot_logs.name
  }
}

# Deployment Information
output "deployment_info" {
  description = "Deployment and configuration information"
  value = {
    region            = var.aws_region
    availability_zone = aws_instance.honeypot_server.availability_zone
    instance_type     = var.instance_type
    vpc_cidr          = var.vpc_cidr
    project_name      = var.project_name
    environment       = var.environment
    deployment_time   = timestamp()
  }
}

# Security Information
output "security_info" {
  description = "Security configuration information"
  value = {
    security_group_id     = aws_security_group.honeypot_sg.id
    iam_role_arn          = aws_iam_role.honeypot_role.arn
    backup_encryption     = "AES256"
    log_retention_days    = var.log_retention_days
    backup_retention_days = var.backup_retention_days
  }
}

# Troubleshooting Information
output "troubleshooting_info" {
  description = "Information for troubleshooting and monitoring"
  value = {
    instance_id       = aws_instance.honeypot_server.id
    public_ip         = aws_instance.honeypot_server.public_ip
    private_ip        = aws_instance.honeypot_server.private_ip
    vpc_id            = aws_vpc.honeypot_vpc.id
    subnet_id         = aws_subnet.honeypot_public_subnet.id
    security_group_id = aws_security_group.honeypot_sg.id
    key_name          = aws_key_pair.honeypot_key.key_name
    cloudwatch_logs   = aws_cloudwatch_log_group.honeypot_logs.name
    s3_backup_bucket  = aws_s3_bucket.honeypot_backup.bucket
  }
}

# Common Tags
output "common_tags" {
  description = "Common tags applied to resources"
  value       = local.common_tags
}