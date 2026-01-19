variable "project_id" {
  description = "The GCP Project ID"
  type        = string
}

variable "region" {
  description = "GCP Region (e.g., us-central1)"
  type        = string
  default     = "europe-west2"
}

variable "db_password" {
  description = "Password for the AlloyDB postgres user"
  type        = string
  sensitive   = true
}
