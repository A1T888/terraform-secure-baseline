# INSECURE BASELINE - intentionally flawed. Never deploy.
# Used to demonstrate what security scanners catch.

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      # FLAW: no version pin
    }
  }
}

provider "aws" {
  region = "ap-southeast-1"
  # FLAW: hardcoded (fake, AWS-documentation example) credentials
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# FLAW: public bucket, no encryption, no versioning, no access logging
resource "aws_s3_bucket" "data" {
  bucket = "portfolio-insecure-data"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}

# FLAW: SSH and all TCP ports open to the internet
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web security group"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# FLAW: no flow logs, default security group left open
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

# FLAW: public IP assigned on launch
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

# FLAW: wildcard IAM policy (full admin)
resource "aws_iam_policy" "admin" {
  name = "everything-allowed"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# FLAW: unencrypted, public, hardcoded password, no backups, no deletion protection
resource "aws_db_instance" "db" {
  identifier              = "insecure-db"
  engine                  = "mysql"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "Password123!"
  publicly_accessible     = true
  storage_encrypted       = false
  skip_final_snapshot     = true
  backup_retention_period = 0
  deletion_protection     = false
}

# FLAW: key rotation disabled
resource "aws_kms_key" "main" {
  description         = "key without rotation"
  enable_key_rotation = false
}

# FLAW: single-region trail, no log validation, no encryption
resource "aws_cloudtrail" "main" {
  name                       = "insecure-trail"
  s3_bucket_name             = aws_s3_bucket.data.id
  is_multi_region_trail      = false
  enable_log_file_validation = false
}
