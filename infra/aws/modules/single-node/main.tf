# The whole engine on one EC2 instance, for the single-node deployment profile: the services, Neo4j
# and Redis as Compose services on one host. Only the gateway port is reachable, and only from the
# security groups and CIDRs given. Administration goes through Session Manager; no SSH port opens.
#
# The host converges itself: withhuman-apply resolves the configured source ref, reads its secrets,
# and brings Compose to that state. A systemd timer runs the same script, so an update is a new
# commit on the ref rather than a Terraform apply.

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

data "aws_ssm_parameter" "al2023" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-${var.architecture}"
}

data "aws_region" "current" {}

locals {
  # Only the keys the host cannot derive itself. withhuman-apply sources this, resolves the ref to
  # a commit, reads the secrets, and exports the result for Compose.
  base_env = merge(
    {
      AWS_REGION           = data.aws_region.current.region
      ENGINE_SECRET_ARN    = var.engine_secret_arn
      JEV_SECRET_ARN       = var.jev_secret_arn
      REGISTRY_SECRET_ARN  = var.registry_secret_arn
      SOURCE_REF           = var.source_ref
      UPDATE_SCHEDULE      = var.update_schedule
      IMAGE_REGISTRY       = var.image_registry
      IMAGE_REGISTRY_HOST  = split("/", var.image_registry)[0]
      GATEWAY_PORT         = tostring(var.gateway_port)
      NEO4J_HEAP_SIZE      = var.neo4j_heap_size
      NEO4J_PAGECACHE_SIZE = var.neo4j_pagecache_size
      DECISION_PROVIDER    = var.decision_provider
      WITHHUMAN_MODE       = var.collector_mode
    },
    var.engine_settings,
  )
}

resource "aws_security_group" "engine" {
  name_prefix = "${var.name}-"
  description = "withhuman engine on ${var.name}"
  vpc_id      = var.vpc_id

  egress {
    description = "Image pulls, the Jev API, AWS APIs and the source repository"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "gateway_from_group" {
  for_each = { for index, id in var.ingress_security_group_ids : tostring(index) => id }

  security_group_id            = aws_security_group.engine.id
  referenced_security_group_id = each.value
  from_port                    = var.gateway_port
  to_port                      = var.gateway_port
  ip_protocol                  = "tcp"
  description                  = "Hooks and MCP traffic from the load balancer"
}

resource "aws_vpc_security_group_ingress_rule" "gateway_from_cidr" {
  for_each = { for index, cidr in var.ingress_cidr_blocks : tostring(index) => cidr }

  security_group_id = aws_security_group.engine.id
  cidr_ipv4         = each.value
  from_port         = var.gateway_port
  to_port           = var.gateway_port
  ip_protocol       = "tcp"
  description       = "Hooks and MCP traffic from the load balancer's subnets"
}

resource "aws_iam_role" "engine" {
  name_prefix = "${var.name}-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.engine.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "secrets" {
  name = "read-engine-secrets"
  role = aws_iam_role.engine.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = compact([
        var.engine_secret_arn,
        var.jev_secret_arn,
        var.registry_secret_arn,
      ])
    }]
  })
}

resource "aws_ssm_parameter" "config" {
  name        = "/withhuman/${var.name}/config"
  description = "Non-secret runtime configuration of ${var.name}"
  type        = "String"
  value = join("\n", [
    for key in sort(keys(local.base_env)) :
    "${key}='${replace(local.base_env[key], "'", "'\\''")}'"
    if local.base_env[key] != ""
  ])
}

resource "aws_iam_role_policy" "config" {
  name = "read-engine-config"
  role = aws_iam_role.engine.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["ssm:GetParameter"]
      Resource = aws_ssm_parameter.config.arn
    }]
  })
}

resource "aws_iam_instance_profile" "engine" {
  name_prefix = "${var.name}-"
  role        = aws_iam_role.engine.name
}

resource "aws_instance" "engine" {
  ami                         = data.aws_ssm_parameter.al2023.value
  instance_type               = var.instance_type
  subnet_id                   = var.subnet_id
  associate_public_ip_address = var.associate_public_ip_address
  vpc_security_group_ids      = [aws_security_group.engine.id]
  iam_instance_profile        = aws_iam_instance_profile.engine.name

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.volume_size
    encrypted   = true
    tags        = { Snapshot = var.name }
  }

  # Changing user_data replaces the instance and the data on its root volume, so only the
  # coordinates that never move are templated in. source_ref and update_schedule are deliberately
  # literal here: both live in Parameter Store, and withhuman-apply applies them -- and corrects the
  # timer's drop-in -- on its first run, so changing either is an in-place update.
  user_data = templatefile("${path.module}/user-data.sh", {
    repository_url        = var.source_repository_url
    source_ref            = "main"
    compose_version       = var.compose_version
    compose_arch          = var.architecture == "arm64" ? "aarch64" : "x86_64"
    update_schedule       = "daily"
    aws_region            = data.aws_region.current.region
    config_parameter_name = aws_ssm_parameter.config.name
  })

  tags = { Name = var.name }

  lifecycle {
    # A newer AMI must not replace the instance and the data on its root volume.
    ignore_changes = [ami]
  }

  depends_on = [
    aws_iam_role_policy.config,
    aws_iam_role_policy.secrets,
    aws_iam_role_policy_attachment.ssm,
  ]
}

resource "aws_iam_role" "snapshots" {
  name_prefix = "${var.name}-dlm-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "dlm.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "snapshots" {
  role       = aws_iam_role.snapshots.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSDataLifecycleManagerServiceRole"
}

# The root volume holds the Neo4j store and the Redis append-only file, so it is the backup.
resource "aws_dlm_lifecycle_policy" "snapshots" {
  description        = "Daily snapshots of ${var.name}"
  execution_role_arn = aws_iam_role.snapshots.arn
  state              = "ENABLED"

  policy_details {
    resource_types = ["VOLUME"]
    target_tags    = { Snapshot = var.name }

    schedule {
      name      = "daily"
      copy_tags = true

      create_rule {
        interval      = 24
        interval_unit = "HOURS"
        times         = ["18:00"]
      }

      retain_rule {
        count = var.snapshot_retention_days
      }
    }
  }
}
