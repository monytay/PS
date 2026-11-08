resource "aws_vpc_security_group_ingress_rule" "bad_modern" {
  security_group_id = "sg-test"
  from_port         = 14
  to_port           = 12
  ip_protocol       = "http"
  cidr_ipv4         = "3.4.5.6"
}