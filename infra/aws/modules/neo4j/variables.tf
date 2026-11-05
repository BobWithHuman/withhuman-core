variable "name" {
  description = "Name of the instance and prefix of its resources."
  type        = string
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  description = "Private subnet of the instance."
  type        = string
}

variable "client_security_group_ids" {
  description = "Security groups allowed to reach Neo4j on 7474 and 7687."
  type        = list(string)
}

variable "password_secret_arn" {
  description = "Secrets Manager secret holding the Neo4j password as a JSON key."
  type        = string
}

variable "password_key" {
  description = "JSON key of the password in the secret."
  type        = string
  default     = "neo4j-password"
}

variable "instance_type" {
  type    = string
  default = "r7i.large"
}

variable "volume_size" {
  description = "Root volume size in GiB; it holds the database."
  type        = number
  default     = 100
}

variable "neo4j_image" {
  type    = string
  default = "neo4j:5.26.0"
}

variable "heap_size" {
  type    = string
  default = "6g"
}

variable "pagecache_size" {
  type    = string
  default = "6g"
}

variable "snapshot_retention_days" {
  type    = number
  default = 7
}
