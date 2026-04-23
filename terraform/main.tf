terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# Enable required APIs
locals {
  services = [
    "securitycenter.googleapis.com",
    "cloudasset.googleapis.com",
    "networkmanagement.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "osconfig.googleapis.com",
    "cloudtasks.googleapis.com",
    "cloudscheduler.googleapis.com",
    "firestore.googleapis.com",
    "bigquery.googleapis.com",
    "chat.googleapis.com",
    "container.googleapis.com",
    "cloudbuild.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com"
  ]
}

resource "google_project_service" "enabled_services" {
  for_each                   = toset(local.services)
  project                    = var.project_id
  service                    = each.key
  disable_dependent_services = true
  disable_on_destroy         = false
}

# Secret Manager for Neo4j Password
resource "google_secret_manager_secret" "neo4j_password" {
  secret_id = "neo4j-password"
  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "neo4j_password_version" {
  secret      = google_secret_manager_secret.neo4j_password.id
  secret_data = var.neo4j_password
}

# Firestore Database Configuration
resource "google_firestore_database" "database" {
  project     = var.project_id
  name        = "(default)"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"
  depends_on  = [google_project_service.enabled_services["firestore.googleapis.com"]]
}
