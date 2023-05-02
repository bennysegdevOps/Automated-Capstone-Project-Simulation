# Create VPC
resource "aws_vpc" "vpc" {
  cidr_block       = var.vpc_cidr
  instance_tenancy = "default"

  tags = {
    Name = "${local.name}-vpc"
  }
}

# Create keypair
resource "aws_key_pair" "eu2acp" {
  key_name   = var.keypair_name
  public_key = file(var.path_to_keypair)
}

# Creating public subnet 1
resource "aws_subnet" "public-subnet-1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.public_subnet1_cidr
  availability_zone = var.az1
  tags = {
    Name = "${local.name}-Public subnet1"
  }
}

# Creating public subnet 2
resource "aws_subnet" "public-subnet-2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.public_subnet2_cidr
  availability_zone = var.az2
  tags = {
    Name = "${local.name}-Public subnet2"
  }
}

# Creating private subnet 1
resource "aws_subnet" "private-subnet-1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.private_subnet1_cidr
  availability_zone = var.az1
  tags = {
    Name = "${local.name}-Private subnet1"
  }
}

# Creating private subnet 2
resource "aws_subnet" "private-subnet-2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.private_subnet2_cidr
  availability_zone = var.az2
  tags = {
    Name = "${local.name}-Private subnet2"
  }
}

# Creating internet gateway
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = {
    Name = "${local.name}-igw"
  }
}

# Create elastic ip
resource "aws_eip" "eip" {
  vpc = true
}

#create a nat gateway
resource "aws_nat_gateway" "ngw" {
  allocation_id = aws_eip.eip.id
  subnet_id     = aws_subnet.public-subnet-1.id
  depends_on = [aws_internet_gateway.igw]     # To ensure proper ordering, it is recommended to add an explicit dependency on the Internet Gateway for the VPC.
  
  tags = {
    Name = "${local.name}-ngw"
  }
}

# Create Route Table
# Public Route Table
resource "aws_route_table" "eu-2-publicRT" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
}

# Private Route Table
resource "aws_route_table" "eu-2-privateRT" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.ngw.id
  }
}

# Create Public Subnet Route Table Association PUB01
resource "aws_route_table_association" "public_subnet_rt-ASC01" {
  subnet_id      = aws_subnet.public-subnet-1.id
  route_table_id = aws_route_table.eu-2-publicRT.id
}

# Create Public Subnet Route Table Association PUB02
resource "aws_route_table_association" "public_subnet_rt-ASC02" {
  subnet_id      = aws_subnet.public-subnet-2.id
  route_table_id = aws_route_table.eu-2-publicRT.id
}

# Create Private Subnet Route Table Association PRIV01
resource "aws_route_table_association" "private_subnet_rt-ASC01" {
  subnet_id      = aws_subnet.private-subnet-1.id
  route_table_id = aws_route_table.eu-2-privateRT.id
}

# Create Private Subnet Route Table Association PRIV02
resource "aws_route_table_association" "private_subnet_rt-ASC02" {
  subnet_id      = aws_subnet.private-subnet-2.id
  route_table_id = aws_route_table.eu-2-privateRT.id
}

# Create Security_Groups Team2-Automated-CapstoneProject_FrontEnd
resource "aws_security_group" "Team2-capstone-sg-frontend" {
  name        = "capstone-sg-frontend"
  description = "frontend_security_group"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "SSH from VPC"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks  = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks  = ["0.0.0.0/0"]
  }
  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks  = ["0.0.0.0/0"]
  }
  egress {
    from_port  = 0
    to_port    = 0
    protocol   = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    name = "${local.name}-sg-frontend"
  }
}

# Create Security_Groups Team2-Automated-CapstoneProject_BackEnd
resource "aws_security_group" "capstone-sg-backend" {
  name        = "capstone-sg-backend"
  description = "backend_security_group"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "mysql access"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.1.0/24", "10.0.2.0/24"]
  }
  egress {
    from_port  = 0
    to_port    = 0
    protocol   = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    name = "${local.name}-sg-backend"
  }
}

# Create wordpress webserver
resource "aws_instance" "wordpress_webserver" {
  ami                         = var.ami_webserver # amazon linux # paris region
  instance_type               = var.instance_type
  associate_public_ip_address = true
  subnet_id                   = aws_subnet.public-subnet-1.id
  key_name                    = aws_key_pair.eu2acp.id
  iam_instance_profile        = aws_iam_instance_profile.iam-instance-profile.id
  vpc_security_group_ids      = [aws_security_group.Team2-capstone-sg-frontend.id]
  user_data                   = <<-EOF
#!/bin/bash
sudo yum update -y
sudo yum upgrade -y
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
sudo yum install unzip -y
unzip awscliv2.zip
sudo ./aws/install
sudo amazon-linux-extras enable php8.2
sudo yum clean metadata
sudo yum install httpd php php-mysqlnd -y
cd /var/www/html
touch indextest.html
echo "Hello World - this is a wordpress test file" > indextest.html
sudo yum install wget -y
wget https://wordpress.org/wordpress-6.1.1.tar.gz
tar -xzf wordpress-6.1.1.tar.gz
cp -r wordpress/* /var/www/html/
rm -rf wordpress
rm -rf wordpress-6.1.1.tar.gz
chmod -R 755 wp-content
chown -R apache:apache wp-content
cd /var/www/html && mv wp-config-sample.php wp-config.php
sed -i "s@define( 'DB_NAME', 'database_name_here' )@define( 'DB_NAME', '${var.db_name}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_USER', 'username_here' )@define( 'DB_USER', '${var.db_username}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_PASSWORD', 'password_here' )@define( 'DB_PASSWORD', '${var.db_password}' )@g" /var/www/html/wp-config.php
sed -i "s@define( 'DB_HOST', 'localhost' )@define( 'DB_HOST', '${element(split(":", aws_db_instance.wordpress-db.endpoint), 0)}')@g" /var/www/html/wp-config.php
cat <<EOT> /etc/httpd/conf/httpd.conf
ServerRoot "/etc/httpd"
Listen 80
Include conf.modules.d/*.conf
User apache
Group apache
ServerAdmin root@localhost
<Directory />
    AllowOverride none
    Require all denied
</Directory>
DocumentRoot "/var/www/html"
<Directory "/var/www">
    AllowOverride None
    # Allow open access:
    Require all granted
</Directory>
<Directory "/var/www/html">
    Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
</Directory>
<IfModule dir_module>
    DirectoryIndex index.html
</IfModule>
<Files ".ht*">
    Require all denied
</Files>
ErrorLog "logs/error_log"
LogLevel warn
<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common
    <IfModule logio_module>
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%%{Referer}i\" \"%%{User-Agent}i\" %I %O" combinedio
    </IfModule>
    CustomLog "logs/access_log" combined
</IfModule>
<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
</IfModule>
<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>
<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>
AddDefaultCharset UTF-8
<IfModule mime_magic_module>
    MIMEMagicFile conf/magic
</IfModule>
EnableSendfile on
IncludeOptional conf.d/*.conf
EOT
cat <<EOT> /var/www/html/.htaccess
Options +FollowSymlinks
RewriteEngine on
rewriterule ^wp-content/uploads/(.*)$ http://${data.aws_cloudfront_distribution.cloudfront.domain_name}/\$1 [r=301,nc]
# BEGIN WordPress
# END WordPress
EOT
aws s3 cp --recursive /var/www/html/ s3://code-bucket-eu2
aws s3 sync /var/www/html/ s3://code-bucket-eu2
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync --delete s3://code-bucket-eu2 /var/www/html/" > /etc/crontab
echo "* * * * * ec2-user /usr/local/bin/aws s3 sync /var/www/html/wp-content/uploads/ s3://media-bucket-eu2" >> /etc/crontab
sudo chkconfig httpd on
sudo service httpd start
sudo setenforce 0
sudo hostnamectl set-hostname webserver 
EOF
  tags = {
    Name = "${local.name}-webserver"
  }
}

#creating database subnet group
resource "aws_db_subnet_group" "team2_capstone_db_subnet_group" {
  name       = "team2_capstone_db_subnet_group"
  subnet_ids = [aws_subnet.private-subnet-1.id, aws_subnet.private-subnet-2.id]

  tags = {
    Name = "${local.name}-DB subnet group"
  }
}

# Creating Mysql wordpress database 
resource "aws_db_instance" "wordpress-db" {
  identifier             = "wordpress-db"
  db_subnet_group_name   = aws_db_subnet_group.team2_capstone_db_subnet_group.id
  vpc_security_group_ids = [aws_security_group.capstone-sg-backend.id]
  multi_az               = true
  allocated_storage      = 10
  db_name                = var.db_name
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  username               = var.db_username
  password               = var.db_password
  parameter_group_name   = "default.mysql5.7"
  skip_final_snapshot    = true
  publicly_accessible    = false
  storage_type           = "gp2"
}

# creating IAM role
resource "aws_iam_role" "iam_role" {
  name = "${local.name}-iam_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    tag-key = "iam_role"
  }
}

# creating media-bucket IAM policy
resource "aws_iam_policy" "s3-policy" {
  name = "${local.name}-s3-policy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:*"]
        Resource = "*"
        Effect   = "Allow"
      },
    ]
  })
}

# Attaching IAM_role_policy to s3 media-bucket policy
resource "aws_iam_role_policy_attachment" "iam-role-attached-to-mediabucket" {
  role       = aws_iam_role.iam_role.name
  policy_arn = aws_iam_policy.s3-policy.arn
}

resource "aws_iam_instance_profile" "iam-instance-profile" {
  name = "${local.name}-instance-profile"
  role = aws_iam_role.iam_role.name
}

# Create s3 media bucket
resource "aws_s3_bucket" "media-bucket" {
  bucket = "media-bucket-eu2"
  force_destroy = true

  tags = {
    Name = "${local.name}-media-bucket"
  }
}

# create s3 log bucket  
resource "aws_s3_bucket" "log-bucket" {
  bucket = "log-bucket-eu2"
  force_destroy = true

  tags = {
    Name        = "${local.name}-log-bucket"
  }
}

# Create S3 code Bucket 
resource "aws_s3_bucket" "code-bucket" {
  bucket        = "code-bucket-eu2"
  force_destroy = true

  tags = {
    Name = "${local.name}-code-bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "media_access" {
  bucket = aws_s3_bucket.media-bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}


resource "aws_s3_bucket_public_access_block" "log_access" {
  bucket = aws_s3_bucket.log-bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

#create access to media bucket
resource "aws_s3_bucket_policy" "allow_access_to_media_bucket" {
  bucket = aws_s3_bucket.media-bucket.id
  policy = data.aws_iam_policy_document.allow_access_to_media_bucket.json
}

data "aws_iam_policy_document" "allow_access_to_media_bucket" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
      "s3:ListBucket",
      "s3:GetObjectVersion",
    ]

    resources = [
      aws_s3_bucket.media-bucket.arn,
      "${aws_s3_bucket.media-bucket.arn}/*",
    ]
  }
}

#create access to log bucket
resource "aws_s3_bucket_policy" "allow_access_to_log_bucket" {
  bucket = aws_s3_bucket.log-bucket.id
  policy = data.aws_iam_policy_document.allow_access_to_log_bucket.json
}

data "aws_iam_policy_document" "allow_access_to_log_bucket" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions = [
      "s3:GetObject",
      "s3:GetBucketAcl",
      "s3:PutBucketAcl",
      "s3:PutObject",
    ]

    resources = [
      aws_s3_bucket.log-bucket.arn,
      "${aws_s3_bucket.log-bucket.arn}/*",
    ]
  }
}

#create log ownership
resource "aws_s3_bucket_ownership_controls" "log_ownership" {
  bucket = aws_s3_bucket.log-bucket.id

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

#create log acl
resource "aws_s3_bucket_acl" "log_acl" {
  depends_on = [aws_s3_bucket_ownership_controls.log_ownership]

  bucket = aws_s3_bucket.log-bucket.id
  acl    = "private"
}

# # Create log bucket policy
# resource "aws_s3_bucket_policy" "log-bucket" {
#   bucket = aws_s3_bucket.log-bucket.id
#   policy = jsonencode({
#     Id = "logBucketPolicy"
#     Statement = [
#       {
#         Action = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject"]
#         Effect = "allow"
#         Principal = {
#           AWS = "*"
#         }
#         Resource = "arn:aws:s3:::log-bucket-eu2/*"
#         Sid      = "PublicReadGetObject"
#       }
#     ]
#     Version = "2012-10-17"
#   })
# }

# # creating media bucket policy
# resource "aws_s3_bucket_policy" "media-bucket" {
#   bucket = aws_s3_bucket.media-bucket.id
#   policy = jsonencode({
#     Id = "mediaBucketPolicy"
#     Statement = [
#       {
#         Action = ["s3:GetObject", "s3:GetObjectVersion"]
#         Effect = "allow"
#         Principal = {
#           AWS = "*"
#         }
#         Resource = "arn:aws:s3:::media-bucket-eu2/*"
#         Sid      = "PublicReadGetObject"
#       }
#     ]
#     Version = "2012-10-17"
#   })
# }

data "aws_cloudfront_distribution" "cloudfront" {
  id = aws_cloudfront_distribution.s3_distribution.id
}

# Creating Cloudfront distribution
locals {
  s3_origin_id = "aws_s3_bucket.media-bucket.id"
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name              = aws_s3_bucket.media-bucket.bucket_domain_name
    origin_id                = local.s3_origin_id
  }
  enabled             = true

  logging_config {
    include_cookies = false
    bucket          = "log-bucket-eu2.s3.amazonaws.com"
    prefix          = "cloudfront-logs"
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }
  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
  viewer_certificate {
    cloudfront_default_certificate = true
  }
}

# Creating Application Load balancer
resource "aws_lb" "eu2acp_alb" {
  name               = "eu2acp-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.Team2-capstone-sg-frontend.id]
  subnets            = [aws_subnet.public-subnet-1.id, aws_subnet.public-subnet-2.id]

  enable_deletion_protection = false

  access_logs {
    bucket  = aws_s3_bucket.log-bucket.id
    prefix  = "lb-logs"
    enabled = true
  }
  tags = {
    Name = "${local.name}-alb"
  }
}

#creating ami from ec2 instance-webserver for snapshot/duplication purposes
resource "aws_ami_from_instance" "webserver_instance_ami" {
  name               = "webserver_instance_ami"
  source_instance_id = aws_instance.wordpress_webserver.id
  snapshot_without_reboot = true
  depends_on = [aws_instance.wordpress_webserver, time_sleep.EC2_wait_time]
}

resource "time_sleep" "EC2_wait_time" {
  depends_on = [aws_instance.wordpress_webserver]
  create_duration = "300s"
}

#Importing hosted zone
data "aws_route53_zone" "project_zone" {
  name         = "thinkeod.com"
  private_zone = false
}
#Create A record 
resource "aws_route53_record" "thinkeod" {
  zone_id = data.aws_route53_zone.project_zone.zone_id
  name    = "thinkeod.com"
  type    = "A"

  alias {
    name                   = aws_lb.eu2acp_alb.dns_name
    zone_id                = aws_lb.eu2acp_alb.zone_id
    evaluate_target_health = true
  }
}

#create acm certificate
resource "aws_acm_certificate" "acm_certificate" {
  domain_name       = "thinkeod.com"
  # subject_alternative_names = ["*.thinkeod.com"]
  validation_method = "DNS"
  lifecycle {
    create_before_destroy = true
  }
}

#create route53 validation record
resource "aws_route53_record" "wordpress_record" {
  for_each = {
    for dvo in aws_acm_certificate.acm_certificate.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.project_zone.zone_id
}

#create acm certificate validition
resource "aws_acm_certificate_validation" "acm_certificate_validation" {
  certificate_arn         = aws_acm_certificate.acm_certificate.arn
  validation_record_fqdns = [for record in aws_route53_record.wordpress_record : record.fqdn]
}

#create launch configuration
resource "aws_launch_configuration" "web_config" {
  name          = "web_config"
  image_id      = aws_ami_from_instance.webserver_instance_ami.id
  instance_type = "t3.medium"
  associate_public_ip_address = true
  iam_instance_profile = aws_iam_instance_profile.iam-instance-profile.id
  security_groups = [aws_security_group.Team2-capstone-sg-frontend.id]
  key_name = aws_key_pair.eu2acp.id
}

#create Auto-Scaling group
resource "aws_autoscaling_group" "Auto_SG" {
  name                      = "Auto_SG"
  max_size                  = 5
  min_size                  = 1
  health_check_grace_period = 300
  health_check_type         = "EC2"
  desired_capacity          = 2
  force_delete              = true
  launch_configuration = aws_launch_configuration.web_config.id
  vpc_zone_identifier = [aws_subnet.public-subnet-1.id, aws_subnet.public-subnet-2.id ]
  target_group_arns = ["${aws_lb_target_group.target_group.arn}"]
  tag {
    key = "name"
    value = "ASG"
    propagate_at_launch = true
  }
}

#Create Auto-Scaling Group Policy
resource "aws_autoscaling_policy" "ASG_policy" {
  autoscaling_group_name = aws_autoscaling_group.Auto_SG.name
  name = "ASG_policy"
  adjustment_type = "ChangeInCapacity"
  policy_type = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 70.0
  }
}

# Create cloudwatch metrics alarm for ASG
resource "aws_cloudwatch_metric_alarm" "asg_cpu_alarm" {
  alarm_name          = "asg-cpu-alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"

  dimensions = {
    AutoScalingGroupName = "${aws_autoscaling_group.Auto_SG.name}"
  }
  alarm_description = "This metric monitors asg average cpu utilization"
  alarm_actions     = [aws_sns_topic.eu2acp-sns-alarm.arn] 
  }


# Create cloudwatch metrics alarm for ec2 instance (webserver)
resource "aws_cloudwatch_metric_alarm" "ec2_cpu_alarm" {
  alarm_name                = "ec2-cpu-alarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "2"
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "80"
  
  dimensions = {
    InstanceId = "${aws_instance.wordpress_webserver.id}"
  }
  alarm_description = "This metric monitors ec2 cpu utilization"
  alarm_actions     = [aws_sns_topic.eu2acp-sns-alarm.arn]
}

# Creating Target Group
resource "aws_lb_target_group" "target_group" {
  name_prefix      = "alb-tg"
  port             = 80
  protocol         = "HTTP"
  vpc_id           = aws_vpc.vpc.id

  health_check {
    interval            = 60
    path                = "/indextest.html"
    port                = 80
    protocol            = "HTTP"
    timeout             = 30
    healthy_threshold   = 3
    unhealthy_threshold = 5
  }
}

# Target Group Attachment
resource "aws_lb_target_group_attachment" "target_group_att" {
  target_group_arn = aws_lb_target_group.target_group.arn
  target_id        = aws_instance.wordpress_webserver.id
  port             = 80
}

# SNS Alarm topic 
resource "aws_sns_topic" "eu2acp-sns-alarm" {
  name            = "eu2acp-sns-alarm"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    }
  }
}
EOF
}
locals {
emails = ["michael.edima@cloudhight.com"]
}

# sns topic subscription 
resource "aws_sns_topic_subscription" "topic_email_subscription" {
count = length(local.emails)
topic_arn = aws_sns_topic.eu2acp-sns-alarm.arn
protocol = "email"
endpoint = local.emails[count.index]
}  

# #create a clouthwatch dashboard that display the average utilization of our ec2 instance[webserver]
# resource "aws_cloudwatch_dashboard" "instance_CPU_uttlisation"{
#   dashboard_name = "instance-CPUUtilizationDashboard"

#   dashboard_body = jsonencode({
#     widget = [ 
#       {
#         type = "metric"
#         properties = {
#           metrics = [
#             ["AWS/EC2", "CPUUtilization", "InstanceId", "${aws_instance.wordpress_webserver.id}", {"label": "Average CPU Utilization"}]
#           ]
#           view = "timeSeries"
#           stacked = false
#           region = "eu-west-3"
#           title = "Average CPU Utilization"
#           period = 300
#           yAxis = {
#             left = {
#               label = "Percentage"
#               showUnits = true
#             }
#           }
#         }
#       }
#     ]
#   })
# } 

# #create a clodwatch dashboard that displays the average CPU utilization for ASG Instances
# resource "aws_cloudwatch_dashboard" "asg_cpu_Utilization_dashboard" {
#   dashboard_name = "ASG-CPUUtilizationDashboard"

#   dashboard_body = jsonencode({
#     widgets = [
#       {
#         type = "metric"
#         properties = {
#           metric = [
#             ["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", "ASG", {"label": "Average CPU Utilization"}]
#           ]
#           view = "timeSeries"
#           stacked = false
#           region = "eu-west-3"
#           title = "Average CPU Utilization"
#           period = 300
#           yAxis = {
#             left = {
#               label = "Percentage"
#               showUnits = true
#             }
#           }
#         }
#       }
#     ]
#   })
# }

#create a clodwatch dashboard that displays the average CPU utilization for ASG Instances

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "my-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            [
              "AWS/EC2",
              "CPUUtilization",
              "AutoScalingGroupName",
              "Auto_SG",
              {"label": "Average CPU Utilization Asg"}
            ]
          ]
          period = 300
          stat   = "Average"
          region = "eu-west-3"
          title  = "Average CPU Utilization Asg"
        }
      },
      {
        type   = "text"
        x      = 0
        y      = 7
        width  = 3
        height = 3

        properties = {
          markdown = "Hello world"
        }
      }
    ]
  })
}

resource "aws_cloudwatch_dashboard" "main2" {
  dashboard_name = "my-dashboard-instance"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            [
              "AWS/EC2",
              "CPUUtilization",
              "InstanceId",
              "${aws_instance.wordpress_webserver.id}",
              {"label": "Average CPU Utilization Instance"}
            ]
          ]
          period = 300
          stat   = "Average"
          region = "eu-west-3"
          title  = "Average CPU Utilization Instance"
        }
      },
      {
        type   = "text"
        x      = 0
        y      = 7
        width  = 3
        height = 3

        properties = {
          markdown = "Hello world 2"
        }
      }
    ]
  })
}

# Creating Load balancer Listener
resource "aws_lb_listener" "eu2acp_lb_listener" {
  load_balancer_arn = aws_lb.eu2acp_alb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "forward"
    target_group_arn = aws_lb_target_group.target_group.arn
    }
  }
  
# Creating a Load balancer Listener for https access
resource "aws_lb_listener" "eu2acp_lb_listener1" {
  load_balancer_arn = aws_lb.eu2acp_alb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "${aws_acm_certificate.acm_certificate.arn}"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.target_group.arn
  }
}