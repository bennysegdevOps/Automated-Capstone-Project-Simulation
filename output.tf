output "webserver-ip" {
  value = aws_instance.wordpress_webserver.public_ip
}

output "alb-dns" {
  value = aws_lb.eu2acp_alb.dns_name
}

output "db-endpoint" {
  value = aws_db_instance.wordpress-db.endpoint
}