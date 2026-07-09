resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length = 8
}

resource "aws_db_instance" "exposed_db" {
  engine              = "postgres"
  publicly_accessible = true
}

resource "aws_security_group" "bad_sg" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "bad_modern" {
  security_group_id = "sg-test"
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}
resource "aws_s3_bucket_public_access_block" "open_bucket" {
  bucket                  = "test-bucket"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_rds_cluster" "unencrypted_cluster" {
  cluster_identifier  = "test-cluster"
  engine              = "aurora-postgresql"
  storage_encrypted   = false
}