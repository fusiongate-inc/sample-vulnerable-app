# Security-hardened Terraform configuration
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "trusted_cidr" {
  description = "Trusted CIDR range for ingress"
  type        = string
  default     = "10.0.0.0/8"
}

resource "aws_s3_bucket" "app_bucket" {
  bucket = "sample-app-terraform-bucket-12345"
  # Fix: Removed public-read ACL - bucket is private by default
}

resource "aws_s3_bucket_acl" "app_bucket_acl" {
  bucket = aws_s3_bucket.app_bucket.id
  acl    = "private"
}

resource "aws_iam_policy" "app_policy" {
  name        = "app-limited-access"
  description = "Policy with least-privilege access for instances"

  # Fix CWE-285: Replace wildcard * actions/resources with specific permissions
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.app_bucket.arn,
          "${aws_s3_bucket.app_bucket.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_security_group" "open_sg" {
  name        = "restricted-sg"
  description = "Security group with restricted access"

  # Fix: Restrict ingress to trusted CIDR and specific ports only
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.trusted_cidr]
  }
}
