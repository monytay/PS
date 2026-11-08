resource "aws_cloudtrail" "unknown_trail" {
  name                  = "unknown-trail"
  s3_bucket_name        = "example-bucket"
  is_multi_region_trail = var.multi_region
  enable_logging        = var.logging
}