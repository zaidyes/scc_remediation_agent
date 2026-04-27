terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "google" {
  region = var.region
}

# --------------------------------------------------------------------------- #
# Folder — isolates all demo resources under one node for easy teardown
# --------------------------------------------------------------------------- #
resource "google_folder" "demo" {
  display_name = var.folder_name
  parent       = "organizations/${var.org_id}"
}

# --------------------------------------------------------------------------- #
# Projects
# --------------------------------------------------------------------------- #
resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  suffix = random_id.suffix.hex

  projects = {
    infra = {
      name       = "demo-infra-${local.suffix}"
      project_id = "demo-infra-${local.suffix}"
    }
    web = {
      name       = "demo-prod-web-${local.suffix}"
      project_id = "demo-prod-web-${local.suffix}"
    }
    data = {
      name       = "demo-prod-data-${local.suffix}"
      project_id = "demo-prod-data-${local.suffix}"
    }
  }
}

resource "google_project" "projects" {
  for_each        = local.projects
  name            = each.value.name
  project_id      = each.value.project_id
  folder_id       = google_folder.demo.folder_id
  billing_account = var.billing_account
}

# --------------------------------------------------------------------------- #
# APIs — only enable what each project needs
# --------------------------------------------------------------------------- #
locals {
  infra_services = [
    "securitycenter.googleapis.com",
    "cloudasset.googleapis.com",
    "networkmanagement.googleapis.com",
    "iam.googleapis.com",
    "osconfig.googleapis.com",
    "cloudtasks.googleapis.com",
    "cloudscheduler.googleapis.com",
    "firestore.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "chat.googleapis.com",
    "container.googleapis.com",
  ]
  workload_services = [
    "compute.googleapis.com",
    "storage.googleapis.com",
    "iam.googleapis.com",
    "osconfig.googleapis.com",
  ]
}

resource "google_project_service" "infra_services" {
  for_each                   = toset(local.infra_services)
  project                    = google_project.projects["infra"].project_id
  service                    = each.key
  disable_dependent_services = true
  disable_on_destroy         = false
  depends_on                 = [google_project.projects]
}

resource "google_project_service" "web_services" {
  for_each                   = toset(local.workload_services)
  project                    = google_project.projects["web"].project_id
  service                    = each.key
  disable_dependent_services = true
  disable_on_destroy         = false
  depends_on                 = [google_project.projects]
}

resource "google_project_service" "data_services" {
  for_each                   = toset(local.workload_services)
  project                    = google_project.projects["data"].project_id
  service                    = each.key
  disable_dependent_services = true
  disable_on_destroy         = false
  depends_on                 = [google_project.projects]
}

# --------------------------------------------------------------------------- #
# Firestore (infra project — agent state)
# --------------------------------------------------------------------------- #
resource "google_firestore_database" "agent_state" {
  project     = google_project.projects["infra"].project_id
  name        = "(default)"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"
  depends_on  = [google_project_service.infra_services]
}

# --------------------------------------------------------------------------- #
# Secret Manager — Neo4j password
# --------------------------------------------------------------------------- #
resource "google_secret_manager_secret" "neo4j_password" {
  secret_id = "neo4j-password"
  project   = google_project.projects["infra"].project_id
  replication { auto {} }
  depends_on = [google_project_service.infra_services]
}

resource "google_secret_manager_secret_version" "neo4j_password" {
  secret      = google_secret_manager_secret.neo4j_password.id
  secret_data = var.neo4j_password
}
