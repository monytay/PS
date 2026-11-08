resource "aws_s3_bucket_public_access_block" "unknown_bucket" {
  bucket                  = "example-bucket"
  block_public_acls       = var.block_acls
  block_public_policy     = var.block_policy
  ignore_public_acls      = var.ignore_acls
  restrict_public_buckets = var.restrict_buckets
}

resource "aws_s3_account_public_access_block" "unknown_account" {
  block_public_acls       = var.block_acls
  block_public_policy     = var.block_policy
  ignore_public_acls      = var.ignore_acls
  restrict_public_buckets = var.restrict_buckets
}