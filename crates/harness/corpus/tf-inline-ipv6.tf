# Inline ingress {} block open to the whole IPv6 internet via a non-canonical
# ::/0 spelling (::0/0) — must be caught like the canonical form.
# EXPECT: High TF-OPEN-SECURITY-GROUP
resource "aws_security_group" "web" {
  ingress {
    from_port        = 22
    to_port          = 22
    ip_protocol      = "tcp"
    ipv6_cidr_blocks = ["::0/0"]
  }
}
