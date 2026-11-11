package main

# Deny any security group that opens SSH (22) to the whole internet.
deny[msg] {
  sg := input.resource.aws_security_group[name]
  ingress := sg.ingress[_]
  ingress.from_port <= 22
  ingress.to_port >= 22
  ingress.cidr_blocks[_] == "0.0.0.0/0"
  msg := sprintf("Security group '%s' allows SSH from the internet", [name])
}

# Require an owner tag on provider-level default tags.
deny[msg] {
  provider := input.provider.aws
  not provider.default_tags
  msg := "AWS provider must define default_tags (including 'owner')"
}
