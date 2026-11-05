resource "aws_vpc_security_group_ingress_rule" "bad_modern" {
  security_group_id = "sg-test"
  from_port         = 3389
  to_port           = 3389
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}