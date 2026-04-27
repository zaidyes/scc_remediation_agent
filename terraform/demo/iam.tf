# --------------------------------------------------------------------------- #
# Agent service account — created in infra project, granted org-level roles
# --------------------------------------------------------------------------- #
resource "google_service_account" "agent_sa" {
  account_id   = "scc-remediation-agent"
  display_name = "SCC Remediation Agent (Demo)"
  project      = google_project.projects["infra"].project_id
  depends_on   = [google_project_service.infra_services]
}

# Org-level — needed to read SCC findings and Cloud Asset Inventory
locals {
  org_roles = [
    "roles/securitycenter.findingsEditor",
    "roles/securitycenter.sourcesViewer",
    "roles/cloudasset.viewer",
    "roles/iam.securityReviewer",
    "roles/networkmanagement.viewer",
    "roles/iam.roleViewer",
    "roles/logging.viewer",
  ]

  # Project-level roles applied to all three demo projects
  project_roles = [
    "roles/compute.securityAdmin",   # modify firewall rules
    "roles/iam.securityAdmin",       # tighten IAM bindings
    "roles/osconfig.patchJobExecutor",
    "roles/storage.admin",           # fix bucket ACLs
  ]

  all_project_ids = [
    google_project.projects["infra"].project_id,
    google_project.projects["web"].project_id,
    google_project.projects["data"].project_id,
  ]

  # Cross product: role × project
  project_role_bindings = {
    for pair in setproduct(local.project_roles, local.all_project_ids) :
    "${pair[0]}__${pair[1]}" => { role = pair[0], project = pair[1] }
  }
}

resource "google_organization_iam_member" "agent_org_roles" {
  for_each = toset(local.org_roles)
  org_id   = var.org_id
  role     = each.key
  member   = "serviceAccount:${google_service_account.agent_sa.email}"
}

resource "google_project_iam_member" "agent_project_roles" {
  for_each = local.project_role_bindings
  project  = each.value.project
  role     = each.value.role
  member   = "serviceAccount:${google_service_account.agent_sa.email}"
}

# Infra-project-only roles
resource "google_project_iam_member" "agent_infra_roles" {
  for_each = toset([
    "roles/datastore.user",
    "roles/cloudtasks.enqueuer",
    "roles/secretmanager.secretAccessor",
    "roles/run.invoker",
  ])
  project = google_project.projects["infra"].project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.agent_sa.email}"
}
