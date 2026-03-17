output "vpc_id" {
  value = aws_vpc.main_vpc.id
}

output "public_subnet_1" {
  value = aws_subnet.public_1.id
}

output "public_subnet_2" {
  value = aws_subnet.public_2.id
}

output "alb_dns_name" {
  value = aws_lb.app_alb.dns_name
}