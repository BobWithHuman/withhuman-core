# Cluster add-ons. Only the AWS parts live here: the Network Load Balancer, and the IAM role that
# External Secrets uses through EKS Pod Identity to read Secrets Manager.

provider "helm" {
  kubernetes = {
    host                   = module.eks.cluster_endpoint
    cluster_ca_certificate = base64decode(module.eks.cluster_certificate_authority_data)
    exec = {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args        = ["eks", "get-token", "--region", var.region, "--cluster-name", module.eks.cluster_name]
    }
  }
}

resource "aws_secretsmanager_secret" "gitops_deploy_key" {
  name                    = "${local.name}/gitops-deploy-key"
  description             = "Read-only deploy key of withhuman-gitops for Argo CD; set its value by hand"
  recovery_window_in_days = var.secret_recovery_window_days
}

resource "aws_iam_role" "external_secrets" {
  name_prefix = "${local.name}-eso-"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "pods.eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
    }]
  })
}

resource "aws_iam_role_policy" "external_secrets" {
  name = "read-withhuman-secrets"
  role = aws_iam_role.external_secrets.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource = [
        aws_secretsmanager_secret.engine.arn,
        aws_secretsmanager_secret.postgres.arn,
        aws_secretsmanager_secret.jev.arn,
        aws_secretsmanager_secret.gitops_deploy_key.arn,
      ]
    }]
  })
}

resource "aws_eks_pod_identity_association" "external_secrets" {
  cluster_name    = module.eks.cluster_name
  namespace       = "external-secrets"
  service_account = "external-secrets"
  role_arn        = aws_iam_role.external_secrets.arn
}

module "platform" {
  source = "../../modules/platform"

  load_balancer_annotations = {
    "service.beta.kubernetes.io/aws-load-balancer-type" = "nlb"
  }
  secret_store_provider = {
    aws = {
      service = "SecretsManager"
      region  = var.region
    }
  }
  acme_email  = var.acme_email
  acme_server = var.acme_server
  # The GitOps repository is public, so Argo CD reads it over https without credentials. Point this
  # back at aws_secretsmanager_secret.gitops_deploy_key.name if the repository returns to private.
  gitops_deploy_key_secret = ""
  gitops_apps_include      = "${var.environment}.yaml"

  # Nodes must run before charts install, and External Secrets needs its role at start.
  depends_on = [module.eks, aws_eks_pod_identity_association.external_secrets]
}
