resource "aws_security_group" "internal" {
  name = "internal"
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 20
  encrypted         = true
}
