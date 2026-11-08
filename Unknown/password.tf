resource "aws_iam_account_password_policy" "unknown_policy" {
  minimum_password_length = var.password_min_length
}