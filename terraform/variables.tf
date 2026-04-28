variable "project_id" {
  description = "The GCP Project ID where the agent is deployed"
  type        = string
}

variable "org_id" {
  description = "The GCP Organization ID where the agent will monitor assets and findings"
  type        = string
}

variable "region" {
  description = "The default region for deployment"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The default zone for deployment"
  type        = string
  default     = "us-central1-a"
}

variable "gke_cluster_name" {
  description = "Name of the GKE cluster for Neo4j"
  type        = string
  default     = "scc-graph-cluster"
}

variable "neo4j_password" {
  description = "Password for the Neo4j database"
  type        = string
  sensitive   = true
}

variable "neo4j_bolt_uri" {
  description = "Bolt URI for the Neo4j instance (e.g. bolt://10.0.0.5:7687)"
  type        = string
  default     = ""
}

variable "event_processor_image" {
  description = "Docker image URI for the event processor Cloud Run service"
  type        = string
  default     = "gcr.io/PROJECT_ID/scc-event-processor:latest"
}

variable "scheduler_service_url" {
  description = "Base URL of the scheduler/webhook Cloud Run service"
  type        = string
  default     = ""
}
