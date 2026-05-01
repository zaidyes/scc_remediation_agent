resource "google_container_cluster" "neo4j_cluster" {
  name     = var.gke_cluster_name
  location = var.zone
  project  = var.project_id

  remove_default_node_pool = true
  initial_node_count       = 1

  # Private cluster — Neo4j is not exposed to the internet (#6 requires VPC-native)
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = "172.16.0.0/28"
  }

  # VPC-native (alias IPs) — required for private clusters (tfsec #6)
  ip_allocation_policy {}

  # Restrict which CIDRs can reach the Kubernetes API server (tfsec #2)
  master_authorized_networks_config {
    dynamic "cidr_blocks" {
      for_each = var.authorized_master_cidr_blocks
      content {
        cidr_block   = cidr_blocks.value.cidr_block
        display_name = cidr_blocks.value.display_name
      }
    }
  }

  # Enable Calico network policy (tfsec #5)
  network_policy {
    enabled  = true
    provider = "CALICO"
  }

  addons_config {
    network_policy_config {
      disabled = false
    }
  }

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Resource labels for asset management (tfsec #7)
  resource_labels = {
    component   = "graph-db"
    managed-by  = "terraform"
    application = "scc-remediation-agent"
  }

  depends_on = [google_project_service.enabled_services["container.googleapis.com"]]
}

resource "google_container_node_pool" "neo4j_nodes" {
  name       = "neo4j-node-pool"
  location   = var.zone
  cluster    = google_container_cluster.neo4j_cluster.name
  project    = var.project_id
  node_count = 1

  # Auto-upgrade and auto-repair for unattended security patching (tfsec #8, #9)
  management {
    auto_upgrade = true
    auto_repair  = true
  }

  node_config {
    machine_type = "e2-standard-4" # Neo4j requires decent memory
    disk_size_gb = 100             # 100Gi storage minimum

    # COS with containerd — Google's hardened node OS (tfsec #10)
    image_type = "COS_CONTAINERD"

    # Disable legacy metadata endpoints — require Metadata-Flavor header (tfsec #3)
    metadata = {
      "disable-legacy-endpoints" = "true"
    }

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
  member             = "serviceAccount:${var.project_id}.svc.id.goog[default/neo4j-sa]"
}
