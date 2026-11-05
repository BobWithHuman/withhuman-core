variable "name" {
  description = "Name of the instance and prefix of its resources."
  type        = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  description = <<-EOT
    Subnet of the instance. A public subnet with associate_public_ip_address keeps the host's
    outbound traffic on the internet gateway, which costs nothing; a private subnet would need a NAT
    gateway for image pulls and the Jev API. The security group, not the subnet, is what keeps the
    host unreachable from the internet.
  EOT
  type        = string
}

variable "associate_public_ip_address" {
  description = "Give the instance a public IP for outbound traffic. See subnet_id."
  type        = bool
  default     = true
}

variable "gateway_port" {
  description = "Host port the gateway listens on; the load balancer's target port."
  type        = number
  default     = 3000
}

variable "ingress_security_group_ids" {
  description = "Security groups allowed to reach the gateway, such as a load balancer's."
  type        = list(string)
  default     = []
}

variable "ingress_cidr_blocks" {
  description = <<-EOT
    CIDRs allowed to reach the gateway, for a load balancer without a security group of its own.
    Leave empty when ingress_security_group_ids covers the callers.
  EOT
  type        = list(string)
  default     = []
}

variable "engine_secret_arn" {
  description = "Secrets Manager secret holding the Neo4j password under the key neo4j-password."
  type        = string
}

variable "jev_secret_arn" {
  description = "Secrets Manager secret holding the Jev API key as its whole value. Required unless decision_provider is mock."
  type        = string
  default     = ""
}

variable "registry_secret_arn" {
  description = <<-EOT
    Secrets Manager secret holding {"username","password"} for a registry that needs a login.
    Empty pulls anonymously, which is what public images need.
  EOT
  type        = string
  default     = ""
}

variable "source_repository_url" {
  description = "Repository the host checks out; it carries the Compose file and the service images' tags."
  type        = string
  default     = "https://github.com/BobWithHuman/withhuman-core.git"
}

variable "source_ref" {
  description = <<-EOT
    Branch, tag or commit the host runs. The images carry their commit SHA, so this one setting
    picks both the Compose file and the build: a tag pins a release, a branch tracks it.
  EOT
  type        = string
  default     = "main"
}

variable "update_schedule" {
  description = "systemd OnCalendar expression for the update timer, such as daily or Mon *-*-* 04:00:00."
  type        = string
  default     = "daily"
}

variable "image_registry" {
  description = "Registry and namespace the service images come from."
  type        = string
  default     = "ghcr.io/bobwithhuman"
}

variable "compose_version" {
  description = "Docker Compose plugin release to install; AL2023 carries no package for it."
  type        = string
  default     = "v2.32.4"
}

variable "instance_type" {
  description = "2 vCPU and 8 GiB holds the engine, Neo4j and Redis on one host."
  type        = string
  default     = "m7i-flex.large"
}

variable "volume_size" {
  description = "Root volume size in GiB; it holds the Neo4j store and the Redis append-only file."
  type        = number
  default     = 100
}

variable "neo4j_heap_size" {
  type    = string
  default = "1g"
}

variable "neo4j_pagecache_size" {
  type    = string
  default = "2g"
}

variable "decision_provider" {
  description = "jev traces each call's cause through Jev; mock answers a fixed verdict and needs no key."
  type        = string
  default     = "jev"

  validation {
    condition     = contains(["jev", "mock"], var.decision_provider)
    error_message = "decision_provider must be jev or mock."
  }
}

variable "collector_mode" {
  description = "record, shadow or enforce."
  type        = string
  default     = "shadow"

  validation {
    condition     = contains(["record", "shadow", "enforce"], var.collector_mode)
    error_message = "collector_mode must be record, shadow or enforce."
  }
}

variable "engine_settings" {
  description = <<-EOT
    Extra WITHHUMAN_* and JEV_* variables for the stack, merged into /etc/withhuman/base.env.
    The Compose file documents the defaults.
  EOT
  type        = map(string)
  default     = {}
}

variable "snapshot_retention_days" {
  type    = number
  default = 7
}
