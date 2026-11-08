resource "aws_cloudtrail" "bad_trail" {
  name                  = "bad-trail"
  s3_bucket_name        = "example-bucket"
  is_multi_region_trail = false
  enable_logging        = false
}