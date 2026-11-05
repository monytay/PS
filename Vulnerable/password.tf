resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length = 8
}
