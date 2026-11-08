resource "aws_vpc_security_group_ingress_rule" "unknown_modern" {
  security_group_id = "sg-12345678"
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
  cidr_ipv4         = var.rdp_cidr
}