output "webserver-ip" {
  value = aws_instance.wordpress_webserver.public_ip
}

output "alb-dns" {
  value = aws_lb.eu2acp_alb.dns_name
}