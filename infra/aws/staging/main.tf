locals {
  name = "withhuman-${var.environment}"
  azs  = slice(data.aws_availability_zones.available.names, 0, 2)
}

data "aws_availability_zones" "available" {
  state = "available"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 6.0"

  name = local.name
  cidr = var.vpc_cidr
  azs  = local.azs

  private_subnets = [for index, _ in local.azs : cidrsubnet(var.vpc_cidr, 4, index)]
  public_subnets  = [for index, _ in local.azs : cidrsubnet(var.vpc_cidr, 8, 48 + index)]

  # One NAT gateway keeps staging cheap; production should use one per zone.
  enable_nat_gateway = true
  single_nat_gateway = var.single_nat_gateway

  public_subnet_tags  = { "kubernetes.io/role/elb" = 1 }
  private_subnet_tags = { "kubernetes.io/role/internal-elb" = 1 }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 21.0"

  name               = local.name
  kubernetes_version = var.kubernetes_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  endpoint_public_access       = true
  endpoint_public_access_cidrs = var.api_allowed_cidrs

  enable_cluster_creator_admin_permissions = true
  access_entries = {
    for arn in var.admin_principal_arns : arn => {
      principal_arn = arn
      policy_associations = {
        admin = {
          policy_arn   = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = { type = "cluster" }
        }
      }
    }
  }

  addons = {
    coredns    = {}
    kube-proxy = {}
    # Enforces the chart's NetworkPolicies, which are standard Kubernetes resources.
    vpc-cni = {
      before_compute       = true
      configuration_values = jsonencode({ enableNetworkPolicy = "true" })
    }
    eks-pod-identity-agent = {
      before_compute = true
    }
  }

  # Plain managed nodes rather than Auto Mode, whose node classes and labels exist only on AWS.
  eks_managed_node_groups = {
    default = {
      ami_type       = "AL2023_x86_64_STANDARD"
      instance_types = var.node_instance_types
      min_size       = var.node_min_size
      max_size       = var.node_max_size
      desired_size   = var.node_desired_size
    }
  }
}

# Secrets the chart's `withhuman` Secret is built from. The Jev key is set by hand, outside
# Terraform, so it never enters the state.
resource "aws_secretsmanager_secret" "engine" {
  name                    = "${local.name}/engine"
  description             = "Redis URL of ${local.name}"
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_secretsmanager_secret_version" "engine" {
  secret_id = aws_secretsmanager_secret.engine.id
  secret_string = jsonencode({
    redis-url = "redis://${aws_elasticache_replication_group.valkey.primary_endpoint_address}:6379"
  })
}

resource "aws_secretsmanager_secret" "jev" {
  name                    = "${local.name}/jev-api-key"
  description             = "Jev API key of ${local.name}; set its value by hand"
  recovery_window_in_days = var.secret_recovery_window_days
}

# Preserve the old database VM and its resources for backup and rollback during the cutover.
removed {
  from = module.neo4j

  lifecycle {
    destroy = false
  }
}

resource "aws_secretsmanager_secret" "postgres" {
  name                    = "${local.name}/database-url"
  description             = "PostgreSQL URL of ${local.name}; set its value by hand"
  recovery_window_in_days = var.secret_recovery_window_days
}

# Valkey speaks the Redis protocol under a BSD license.
resource "aws_elasticache_subnet_group" "valkey" {
  name       = local.name
  subnet_ids = module.vpc.private_subnets
}

resource "aws_security_group" "valkey" {
  name_prefix = "${local.name}-valkey-"
  description = "Valkey for ${local.name}"
  vpc_id      = module.vpc.vpc_id

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "valkey" {
  security_group_id            = aws_security_group.valkey.id
  referenced_security_group_id = module.eks.node_security_group_id
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
  description                  = "Valkey from the engine services"
}

resource "aws_elasticache_replication_group" "valkey" {
  replication_group_id = local.name
  description          = "Collector shared state for ${local.name}"
  engine               = "valkey"
  engine_version       = var.valkey_version
  node_type            = var.valkey_node_type
  num_cache_clusters   = 1
  port                 = 6379

  subnet_group_name  = aws_elasticache_subnet_group.valkey.name
  security_group_ids = [aws_security_group.valkey.id]

  at_rest_encryption_enabled = true
  # The Collector's Redis client is built without TLS; only the cluster's nodes reach this port.
  transit_encryption_enabled = false
}
