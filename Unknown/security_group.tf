resource "aws_security_group" "unknown_sg" {
  name = "unknown-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidrs   # unknown CIDR
  }
}

resource "aws_security_group_rule" "unknown_rule" {
  type              = "ingress"
  security_group_id = "sg-12345678"
  from_port         = var.admin_port   # unknown port, CIDR is open
  to_port           = var.admin_port
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}