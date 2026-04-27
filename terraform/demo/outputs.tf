output "infra_project_id" {
  description = "Project ID where the agent runs."
  value       = google_project.projects["infra"].project_id
}

output "web_project_id" {
  description = "Demo web workload project (misconfigured firewall + VM)."
  value       = google_project.projects["web"].project_id
}

output "data_project_id" {
  description = "Demo data project (public bucket + over-permissioned SA)."
  value       = google_project.projects["data"].project_id
}

output "agent_sa_email" {
  description = "Service account email for the agent."
  value       = google_service_account.agent_sa.email
}

output "demo_folder_id" {
  description = "Folder ID — delete this to tear down the entire demo."
  value       = google_folder.demo.folder_id
}

output "neo4j_secret_name" {
  description = "Secret Manager resource name for the Neo4j password."
  value       = google_secret_manager_secret.neo4j_password.name
}

output "neo4j_internal_ip" {
  description = "Internal IP of the Neo4j VM. Use with IAP tunnel for local access."
  value       = google_compute_address.neo4j_internal.address
}

output "neo4j_instance_name" {
  description = "Compute Engine instance name for the Neo4j VM."
  value       = google_compute_instance.neo4j.name
}

output "neo4j_zone" {
  description = "Zone where the Neo4j VM is running."
  value       = google_compute_instance.neo4j.zone
}

output "neo4j_bolt_uri" {
  description = "Bolt URI for the agent to connect to Neo4j (internal network)."
  value       = "bolt://${google_compute_address.neo4j_internal.address}:7687"
}
