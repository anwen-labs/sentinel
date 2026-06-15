# EXPECT: High TF-OPEN-SECURITY-GROUP
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
