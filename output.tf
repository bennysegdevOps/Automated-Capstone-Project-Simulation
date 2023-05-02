output "webserver-ip" {
  value = aws_instance.wordpress_webserver.public_ip
}