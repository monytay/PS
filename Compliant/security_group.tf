resource "aws_security_group" "bad_sg" {
  ingress {
    from_port   = 12
    to_port     = 14
    protocol    = "http"
    cidr_blocks = ["1.2.3.4"]
  }
}