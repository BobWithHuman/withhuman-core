# Neo4j on one EC2 instance in a private subnet. Only the given security groups reach it, and its
# root volume, which holds the data, is snapshotted daily.

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
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

data "aws_region" "current" {}

resource "aws_security_group" "neo4j" {
  name_prefix = "${var.name}-"
  description = "Neo4j for ${var.name}"
  vpc_id      = var.vpc_id

  egress {
    description = "Image pulls and AWS APIs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "neo4j" {
  for_each = {
    for pair in setproduct(range(length(var.client_security_group_ids)), [7474, 7687]) :
    "${pair[0]}-${pair[1]}" => {
      group = var.client_security_group_ids[pair[0]]
      port  = pair[1]
    }
  }

  security_group_id            = aws_security_group.neo4j.id
  referenced_security_group_id = each.value.group
  from_port                    = each.value.port
  to_port                      = each.value.port
  ip_protocol                  = "tcp"
  description                  = "Neo4j from the engine services"
}

resource "aws_iam_role" "neo4j" {
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

# Administration goes through Session Manager; the instance opens no SSH port.
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.neo4j.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "password" {
  name = "read-neo4j-password"
  role = aws_iam_role.neo4j.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "secretsmanager:GetSecretValue"
      Resource = var.password_secret_arn
    }]
  })
}

resource "aws_iam_instance_profile" "neo4j" {
  name_prefix = "${var.name}-"
  role        = aws_iam_role.neo4j.name
}

resource "aws_instance" "neo4j" {
  ami                    = data.aws_ssm_parameter.al2023.value
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.neo4j.id]
  iam_instance_profile   = aws_iam_instance_profile.neo4j.name

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.volume_size
    encrypted   = true
    tags        = { Snapshot = var.name }
  }

  user_data = templatefile("${path.module}/user-data.sh", {
    region         = data.aws_region.current.region
    secret_arn     = var.password_secret_arn
    password_key   = var.password_key
    neo4j_image    = var.neo4j_image
    heap_size      = var.heap_size
    pagecache_size = var.pagecache_size
  })

  tags = { Name = var.name }

  lifecycle {
    # A newer AMI must not replace the instance and its data.
    ignore_changes = [ami]
  }

  depends_on = [
    aws_iam_role_policy.password,
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
