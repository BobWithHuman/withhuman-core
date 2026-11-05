variable "load_balancer_annotations" {
  description = "Annotations for Traefik's LoadBalancer Service; they choose the cloud's load balancer."
  type        = map(string)
  default     = {}
}

variable "secret_store_name" {
  description = "Name of the ClusterSecretStore that the engine's ExternalSecret refers to."
  type        = string
  default     = "cloud-secrets"
}

variable "secret_store_provider" {
  description = "The cloud's External Secrets provider block, such as { aws = { service = \"SecretsManager\", region = \"...\" } }."
  type        = any
}

variable "acme_email" {
  description = "Contact for the Let's Encrypt account."
  type        = string
}

variable "acme_server" {
  description = "ACME directory. Use the staging directory while testing to avoid rate limits."
  type        = string
  default     = "https://acme-v02.api.letsencrypt.org/directory"
}

variable "gitops_repository_url" {
  description = "An https:// URL needs no credentials while the repository is public; an SSH URL needs gitops_deploy_key_secret."
  type        = string
  default     = "https://github.com/BobWithHuman/withhuman-gitops.git"
}

variable "gitops_deploy_key_secret" {
  description = "Secret in the cloud's secret store holding the read-only deploy key of the GitOps repository. Leave empty for a repository Argo CD reads without credentials."
  type        = string
  default     = ""
}

variable "gitops_apps_path" {
  description = "Directory of the GitOps repository with the Argo CD Applications."
  type        = string
  default     = "apps"
}

variable "gitops_apps_include" {
  description = "File of that directory this cluster runs, such as staging.yaml."
  type        = string
}

variable "cert_manager_version" {
  type    = string
  default = "v1.21.3"
}

variable "external_secrets_version" {
  type    = string
  default = "2.14.0"
}

variable "traefik_version" {
  type    = string
  default = "42.3.0"
}

variable "argocd_version" {
  type    = string
  default = "10.12.1"
}
