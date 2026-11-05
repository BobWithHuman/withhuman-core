variable "region" {
  type    = string
  default = "ap-northeast-2"
}

variable "name" {
  description = "Name used for the instance and supporting resources."
  type        = string
  default     = "withhuman-personal"
}

variable "vpc_cidr" {
  type    = string
  default = "10.30.0.0/16"
}

variable "domain_name" {
  description = "Public hostname used by Claude Code, such as withhuman.example.com."
  type        = string
}

variable "route53_zone_id" {
  description = "Route 53 public hosted-zone ID that owns domain_name."
  type        = string
}

variable "source_ref" {
  description = "Release tag, commit SHA, or branch followed by the host. Pin a tag for stability."
  type        = string
  default     = "main"
}

variable "update_schedule" {
  description = "systemd OnCalendar expression used to poll source_ref."
  type        = string
  default     = "daily"
}

variable "instance_type" {
  type    = string
  default = "m7i-flex.large"
}

variable "volume_size" {
  type    = number
  default = 100
}

variable "collector_mode" {
  type    = string
  default = "shadow"

  validation {
    condition     = contains(["record", "shadow", "enforce"], var.collector_mode)
    error_message = "collector_mode must be record, shadow or enforce."
  }
}

variable "registry_secret_arn" {
  description = "Optional Secrets Manager ARN holding registry username and password."
  type        = string
  default     = ""
}

variable "engine_settings" {
  description = "Additional WITHHUMAN_* and JEV_* runtime settings."
  type        = map(string)
  default     = {}
}

variable "secret_recovery_window_days" {
  type    = number
  default = 7
}
