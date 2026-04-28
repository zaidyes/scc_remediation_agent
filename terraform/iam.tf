resource "google_service_account" "scc_agent_sa" {
  account_id   = "scc-remediation-agent"
  display_name = "SCC Remediation Agent Service Account"
  project      = var.project_id
}

# Organization-level roles
locals {
  org_roles = [
    "roles/securitycenter.findingsViewer",
    "roles/securitycenter.findingsMuteSetter",
    # CAI feed management — required for infrastructure/setup_feeds.py
    "roles/cloudasset.owner",
    "roles/iam.securityReviewer",
    "roles/networkmanagement.viewer",
    "roles/osconfig.patchJobExecutor",
    "roles/iam.roleViewer",
    "roles/logging.viewer",
    "roles/monitoring.viewer",
    # Cloud Logging org-level sink — required for infrastructure/setup_log_sink.py
    "roles/logging.configWriter",
  ]
}

resource "google_organization_iam_member" "agent_org_roles" {
  for_each = toset(local.org_roles)
  org_id   = var.org_id
  role     = each.key
  member   = "serviceAccount:${google_service_account.scc_agent_sa.email}"
}

# Project-level roles
locals {
  project_roles = [
    "roles/iam.securityAdmin", # Required if IAM tightening is enabled
    "roles/compute.viewer",
    "roles/osconfig.instanceViewer",
    "roles/secretmanager.secretAccessor" # Needed to read Neo4j password
  ]
}

resource "google_project_iam_member" "agent_project_roles" {
  for_each = toset(local.project_roles)
  project  = var.project_id
  role     = each.key
  member   = "serviceAccount:${google_service_account.scc_agent_sa.email}"
}

# Grant the Cloud Asset Inventory service agent publish rights on the
# asset-change-events topic so CAI feeds can deliver messages.
resource "google_pubsub_topic_iam_member" "cai_publisher" {
  project = var.project_id
  topic   = "asset-change-events"
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-cloudasset.iam.gserviceaccount.com"
}

# Agent SA: enqueue Cloud Tasks for escalation and execution
resource "google_project_iam_member" "agent_tasks_enqueuer" {
  project = var.project_id
  role    = "roles/cloudtasks.enqueuer"
  member  = "serviceAccount:${google_service_account.scc_agent_sa.email}"
}

# Agent SA: act as itself when signing Cloud Tasks OIDC tokens
resource "google_service_account_iam_member" "agent_sa_token_creator" {
  service_account_id = google_service_account.scc_agent_sa.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = "serviceAccount:${google_service_account.scc_agent_sa.email}"
}

# Cloud Build Service Account (for Terraform PRs)
resource "google_service_account" "cloudbuild_sa" {
  account_id   = "scc-agent-cloudbuild"
  display_name = "SCC Agent Cloud Build Service Account"
  project      = var.project_id
}

resource "google_project_iam_member" "cloudbuild_viewer" {
  project = var.project_id
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.cloudbuild_sa.email}"
}
