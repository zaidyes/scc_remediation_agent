variable "org_id" {
  description = "The GCP Organization ID to deploy the demo environment under."
  type        = string

  validation {
    condition     = can(regex("^[0-9]+$", var.org_id))
    error_message = "org_id must be a numeric GCP Organization ID (e.g. 123456789012)."
  }
}

variable "billing_account" {
  description = "The billing account ID to attach to demo projects (format: XXXXXX-XXXXXX-XXXXXX)."
  type        = string

  validation {
    condition     = can(regex("^[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}$", var.billing_account))
    error_message = "billing_account must be in the format XXXXXX-XXXXXX-XXXXXX."
  }
}

variable "region" {
  description = "Default region for demo resources."
  type        = string
  default     = "us-central1"
}

variable "neo4j_password" {
  description = "Password for the Neo4j demo instance."
  type        = string
  sensitive   = true
}

variable "folder_name" {
  description = "Display name for the demo folder under the org."
  type        = string
  default     = "scc-agent-demo"
}

variable "event_processor_image" {
  description = "Docker image URI for the event processor Cloud Run service."
  type        = string
  default     = "gcr.io/PROJECT_ID/scc-event-processor:latest"
}
