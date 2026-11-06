variable "region" {
  type    = string
  default = "ap-northeast-2"
}

variable "environment" {
  type    = string
  default = "staging"
}

variable "vpc_cidr" {
  type    = string
  default = "10.20.0.0/16"
}

variable "single_nat_gateway" {
  type    = bool
  default = true
}

variable "kubernetes_version" {
  description = "EKS version; list the current ones with `aws eks describe-cluster-versions`."
  type        = string
}

variable "api_allowed_cidrs" {
  description = "CIDRs allowed to reach the Kubernetes API, such as the office and CI runners."
  type        = list(string)
}

variable "admin_principal_arns" {
  description = "IAM roles or users given cluster admin, besides whoever runs Terraform."
  type        = list(string)
  default     = []
}

variable "node_instance_types" {
  type    = list(string)
  default = ["m7i.large"]
}

variable "node_min_size" {
  type    = number
  default = 2
}

variable "node_max_size" {
  type    = number
  default = 4
}

variable "node_desired_size" {
  type    = number
  default = 2
}

variable "valkey_version" {
  type    = string
  default = "8.0"
}

variable "valkey_node_type" {
  type    = string
  default = "cache.t4g.small"
}

variable "acme_email" {
  description = "Contact for the Let's Encrypt account that issues the Ingress certificates."
  type        = string
}

variable "acme_server" {
  description = "Use https://acme-staging-v02.api.letsencrypt.org/directory while testing."
  type        = string
  default     = "https://acme-v02.api.letsencrypt.org/directory"
}

variable "secret_recovery_window_days" {
  description = "0 deletes secrets at once, so a destroyed staging can be recreated with the same names."
  type        = number
  default     = 0
}
