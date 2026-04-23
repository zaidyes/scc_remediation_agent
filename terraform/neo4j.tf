resource "google_container_cluster" "neo4j_cluster" {
  name     = var.gke_cluster_name
  location = var.zone
  project  = var.project_id

  remove_default_node_pool = true
  initial_node_count       = 1

  # We recommend a private cluster so Neo4j is not exposed to the internet.
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  depends_on = [google_project_service.enabled_services["container.googleapis.com"]]
}

resource "google_container_node_pool" "neo4j_nodes" {
  name       = "neo4j-node-pool"
  location   = var.zone
  cluster    = google_container_cluster.neo4j_cluster.name
  project    = var.project_id
  node_count = 1

  node_config {
    machine_type = "e2-standard-4" # Neo4j requires decent memory
    disk_size_gb = 100             # 100Gi storage minimum

    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    service_account = google_service_account.scc_agent_sa.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]
  }
}

# IAM Binding for Workload Identity
resource "google_service_account_iam_member" "workload_identity_binding" {
  service_account_id = google_service_account.scc_agent_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[default/neo4j-sa]" # Assuming default namespace and sa name
}
