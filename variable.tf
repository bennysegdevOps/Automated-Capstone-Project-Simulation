# vpc cidr block
variable "vpc_cidr" {
  default = "10.0.0.0/16"
}

# keypair name
variable "keypair_name" {
  default = "eu2capstone_keypair"
}

# path to keypair
variable "path_to_keypair" {
  default = "~/Keypairs/eu2acp.pub"
}

# media bucket name
variable "media-bucket-name" {
  default = "media-bucket-eu2"
}

# public subnet-1 cidr block
variable "public_subnet1_cidr" {
  default = "10.0.1.0/24"
}

# availability zone public subnet 1
variable "az1" {
  default = "eu-west-1a"
}

# public subnet-2 cidr block
variable "public_subnet2_cidr" {
  default = "10.0.2.0/24"
}

# availability zone public subnet 2
variable "az2" {
  default = "eu-west-1b"
}

# private subnet-1 cidr block
variable "private_subnet1_cidr" {
  default = "10.0.3.0/24"
}

# private subnet-2 cidr block
variable "private_subnet2_cidr" {
  default = "10.0.4.0/24"
}

# all traffic cidr block
variable "all_traffic_cidr" {
  default = "0.0.0.0/0"
}

# ssh port 
variable "ssh_port" {
  default = "22"
}

# https port
variable "https_port" {
  default = "443"
}

# http port
variable "http_port" {
  default = "80"
}

# mysql port
variable "mysql_port" {
  default = "3306"
}
# webserver ami
variable "ami_webserver" {
  default = "ami-00b1c9efd33fda707"
}

# webserver instance type
variable "instance_type" {
  default = "t2.micro"
}

# database name
variable "db_name" {
  default = "wordpress_db"
}

# database username
variable "db_username" {
  default = "admin"
}

# database password
variable "db_password" {
  default = "Admin123"
}