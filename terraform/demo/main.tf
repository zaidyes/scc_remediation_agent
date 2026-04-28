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
    "pubsub.googleapis.com",
    "logging.googleapis.com",
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

# --------------------------------------------------------------------------- #
# Pub/Sub — event bus for CAI feeds and audit logs
# --------------------------------------------------------------------------- #

resource "google_pubsub_topic" "asset_change_events" {
  name    = "asset-change-events"
  project = google_project.projects["infra"].project_id
  depends_on = [google_project_service.infra_services]
}

resource "google_pubsub_topic" "audit_change_events" {
  name    = "audit-change-events"
  project = google_project.projects["infra"].project_id
  depends_on = [google_project_service.infra_services]
}

resource "google_pubsub_topic" "event_processor_dlq" {
  name                       = "event-processor-dlq"
  project                    = google_project.projects["infra"].project_id
  message_retention_duration = "86400s"
  depends_on                 = [google_project_service.infra_services]
}

# --------------------------------------------------------------------------- #
# Event processor Cloud Run service
# --------------------------------------------------------------------------- #

resource "google_service_account" "event_processor_sa" {
  account_id   = "event-processor"
  display_name = "SCC Agent Event Processor"
  project      = google_project.projects["infra"].project_id
}

resource "google_service_account" "event_processor_invoker_sa" {
  account_id   = "event-processor-invoker"
  display_name = "Pub/Sub → Event Processor invoker"
  project      = google_project.projects["infra"].project_id
}

resource "google_cloud_run_v2_service" "event_processor" {
  name     = "scc-event-processor"
  location = var.region
  project  = google_project.projects["infra"].project_id

  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.event_processor_sa.email

    containers {
      image = var.event_processor_image

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = google_project.projects["infra"].project_id
      }
      env {
        name  = "NEO4J_URI"
        value = "bolt://${module.neo4j.neo4j_internal_ip}:7687"
      }
      env {
        name = "NEO4J_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.neo4j_password.secret_id
            version = "latest"
          }
        }
      }
      env {
        name  = "SCHEDULER_SERVICE_URL"
        value = google_cloud_run_v2_service.scheduler.uri
      }
      env {
        name  = "CLOUD_TASKS_LOCATION"
        value = var.region
      }
      env {
        name  = "CLOUD_TASKS_QUEUE"
        value = "scc-remediation-tasks"
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }
  }

  depends_on = [
    google_project_service.infra_services,
    google_secret_manager_secret_version.neo4j_password,
  ]
}

resource "google_pubsub_subscription" "asset_events_push" {
  name    = "asset-events-processor-push"
  topic   = google_pubsub_topic.asset_change_events.id
  project = google_project.projects["infra"].project_id

  push_config {
    push_endpoint = "${google_cloud_run_v2_service.event_processor.uri}/events/asset"
    oidc_token {
      service_account_email = google_service_account.event_processor_invoker_sa.email
    }
  }

  ack_deadline_seconds       = 60
  message_retention_duration = "600s"

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.event_processor_dlq.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "300s"
  }
}

resource "google_pubsub_subscription" "audit_events_push" {
  name    = "audit-events-processor-push"
  topic   = google_pubsub_topic.audit_change_events.id
  project = google_project.projects["infra"].project_id

  push_config {
    push_endpoint = "${google_cloud_run_v2_service.event_processor.uri}/events/audit"
    oidc_token {
      service_account_email = google_service_account.event_processor_invoker_sa.email
    }
  }

  ack_deadline_seconds       = 60
  message_retention_duration = "600s"

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.event_processor_dlq.id
    max_delivery_attempts = 5
  }

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "300s"
  }
}

resource "google_cloud_run_v2_service_iam_member" "event_processor_invoker" {
  project  = google_project.projects["infra"].project_id
  location = var.region
  name     = google_cloud_run_v2_service.event_processor.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.event_processor_invoker_sa.email}"
}

resource "google_project_iam_member" "event_processor_firestore" {
  project = google_project.projects["infra"].project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.event_processor_sa.email}"
}

resource "google_project_iam_member" "event_processor_tasks_enqueuer" {
  project = google_project.projects["infra"].project_id
  role    = "roles/cloudtasks.enqueuer"
  member  = "serviceAccount:${google_service_account.event_processor_sa.email}"
}

resource "google_project_iam_member" "event_processor_secret_accessor" {
  project = google_project.projects["infra"].project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.event_processor_sa.email}"
}
