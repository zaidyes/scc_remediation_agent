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
    "roles/cloudasset.viewer",
    "roles/iam.securityReviewer",
    "roles/networkmanagement.viewer",
    "roles/osconfig.patchJobExecutor",
    "roles/iam.roleViewer",
    "roles/logging.viewer",
    "roles/monitoring.viewer"
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
