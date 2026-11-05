locals {
  azs = slice(data.aws_availability_zones.available.names, 0, 2)
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.0"

  name = var.name
  cidr = var.vpc_cidr
  azs  = local.azs

  public_subnets       = [for index, _ in local.azs : cidrsubnet(var.vpc_cidr, 8, index)]
  enable_nat_gateway   = false
  enable_dns_hostnames = true
}

resource "random_password" "neo4j" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "engine" {
  name                    = "${var.name}/engine"
  description             = "Neo4j password of ${var.name}"
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "engine" {
  secret_id = aws_secretsmanager_secret.engine.id
  secret_string = jsonencode({
    neo4j-password = random_password.neo4j.result
  })
}

resource "aws_secretsmanager_secret" "jev" {
  name                    = "${var.name}/jev-api-key"
  description             = "Jev API key of ${var.name}; set its value after apply"
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  description = "Public HTTPS entry point of ${var.name}"
  vpc_id      = module.vpc.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  description       = "Redirect HTTP to HTTPS"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Claude Code hooks over HTTPS"
}

module "engine" {
  source = "../modules/single-node"

  name                        = var.name
  vpc_id                      = module.vpc.vpc_id
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = true
  ingress_security_group_ids  = [aws_security_group.alb.id]
  engine_secret_arn           = aws_secretsmanager_secret.engine.arn
  jev_secret_arn              = aws_secretsmanager_secret.jev.arn
  registry_secret_arn         = var.registry_secret_arn
  source_ref                  = var.source_ref
  update_schedule             = var.update_schedule
  instance_type               = var.instance_type
  architecture                = var.architecture
  volume_size                 = var.volume_size
  collector_mode              = var.collector_mode
  engine_settings             = var.engine_settings

  depends_on = [aws_secretsmanager_secret_version.engine]
}

resource "aws_acm_certificate" "engine" {
  domain_name       = var.domain_name
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "certificate" {
  for_each = {
    for option in aws_acm_certificate.engine.domain_validation_options : option.domain_name => {
      name   = option.resource_record_name
      record = option.resource_record_value
      type   = option.resource_record_type
    }
  }

  zone_id = var.route53_zone_id
  name    = each.value.name
  type    = each.value.type
  records = [each.value.record]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "engine" {
  certificate_arn         = aws_acm_certificate.engine.arn
  validation_record_fqdns = [for record in aws_route53_record.certificate : record.fqdn]
}

resource "aws_lb" "engine" {
  name               = substr(var.name, 0, 32)
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = module.vpc.public_subnets
}

resource "aws_lb_target_group" "engine" {
  name        = substr("${var.name}-engine", 0, 32)
  port        = module.engine.gateway_port
  protocol    = "HTTP"
  vpc_id      = module.vpc.vpc_id
  target_type = "instance"

  health_check {
    enabled             = true
    path                = "/healthz"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 15
    matcher             = "200"
  }
}

resource "aws_lb_target_group_attachment" "engine" {
  target_group_arn = aws_lb_target_group.engine.arn
  target_id        = module.engine.instance_id
  port             = module.engine.gateway_port
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.engine.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.engine.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.engine.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.engine.arn
  }
}

resource "aws_route53_record" "engine" {
  zone_id = var.route53_zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = aws_lb.engine.dns_name
    zone_id                = aws_lb.engine.zone_id
    evaluate_target_health = true
  }
}
