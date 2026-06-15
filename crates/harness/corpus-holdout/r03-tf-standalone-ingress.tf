# EXPECT: High TF-OPEN-SECURITY-GROUP
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = "sg-0123456789"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
