# Cluster add-ons the engine needs on any cloud: Argo CD, Traefik for Ingress, cert-manager and
# External Secrets. A cloud's root module supplies what differs: the load balancer annotations and
# the External Secrets provider.

terraform {
  required_version = ">= 1.10"

  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "~> 3.0"
    }
  }
}

resource "helm_release" "cert_manager" {
  name             = "cert-manager"
  namespace        = "cert-manager"
  create_namespace = true
  repository       = "https://charts.jetstack.io"
  chart            = "cert-manager"
  version          = var.cert_manager_version

  values = [yamlencode({
    crds = { enabled = true }
  })]
}

resource "helm_release" "external_secrets" {
  name             = "external-secrets"
  namespace        = "external-secrets"
  create_namespace = true
  repository       = "https://charts.external-secrets.io"
  chart            = "external-secrets"
  version          = var.external_secrets_version

  values = [yamlencode({
    serviceAccount = { name = "external-secrets" }
  })]
}

resource "helm_release" "traefik" {
  name             = "traefik"
  namespace        = "traefik"
  create_namespace = true
  repository       = "https://traefik.github.io/charts"
  chart            = "traefik"
  version          = var.traefik_version

  values = [yamlencode({
    ingressClass = { enabled = true, isDefaultClass = true, name = "traefik" }
    deployment   = { replicas = 2 }
    podDisruptionBudget = {
      enabled      = true
      minAvailable = 1
    }
    ports = {
      web = {
        # cert-manager answers HTTP-01 challenges on port 80; everything else moves to HTTPS.
        allowACMEByPass = true
        http = {
          redirections = {
            entryPoint = { to = "websecure", scheme = "https", permanent = true }
          }
        }
      }
    }
    service = {
      annotations = var.load_balancer_annotations
    }
  })]
}

resource "helm_release" "argocd" {
  name             = "argocd"
  namespace        = "argocd"
  create_namespace = true
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-cd"
  version          = var.argocd_version

  # Reached with `kubectl port-forward`; it is not exposed through the Ingress.
  values = [yamlencode({
    dex = { enabled = false }
  })]
}

# The cluster-wide objects that use the add-ons' CRDs. A chart of its own installs them after the
# CRDs exist, which a plan of Kubernetes manifests could not wait for.
resource "helm_release" "config" {
  name      = "platform-config"
  namespace = "argocd"
  chart     = "${path.module}/chart"

  values = [yamlencode({
    secretStore = {
      name     = var.secret_store_name
      provider = var.secret_store_provider
    }
    certificates = {
      email        = var.acme_email
      server       = var.acme_server
      ingressClass = "traefik"
    }
    gitops = {
      url       = var.gitops_repository_url
      secretKey = var.gitops_deploy_key_secret
      path      = var.gitops_apps_path
      include   = var.gitops_apps_include
    }
  })]

  depends_on = [
    helm_release.cert_manager,
    helm_release.external_secrets,
    helm_release.traefik,
    helm_release.argocd,
  ]
}
