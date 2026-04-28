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
    "secretmanager.googleapis.com",
    "pubsub.googleapis.com",
    "logging.googleapis.com",
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

# ---------------------------------------------------------------------------
# Pub/Sub — event bus for CAI feeds and Cloud Audit Logs
# ---------------------------------------------------------------------------

resource "google_pubsub_topic" "asset_change_events" {
  name    = "asset-change-events"
  project = var.project_id
  depends_on = [google_project_service.enabled_services["pubsub.googleapis.com"]]
}

resource "google_pubsub_topic" "audit_change_events" {
  name    = "audit-change-events"
  project = var.project_id
  depends_on = [google_project_service.enabled_services["pubsub.googleapis.com"]]
}

# Dead-letter topic for undeliverable messages (24-hour retention)
resource "google_pubsub_topic" "event_processor_dlq" {
  name    = "event-processor-dlq"
  project = var.project_id
  message_retention_duration = "86400s"
  depends_on = [google_project_service.enabled_services["pubsub.googleapis.com"]]
}

resource "google_pubsub_subscription" "asset_events_push" {
  name    = "asset-events-processor-push"
  topic   = google_pubsub_topic.asset_change_events.id
  project = var.project_id

  push_config {
    push_endpoint = "${google_cloud_run_v2_service.event_processor.uri}/events/asset"
    oidc_token {
      service_account_email = google_service_account.event_processor_invoker_sa.email
    }
  }

  ack_deadline_seconds       = 60
  message_retention_duration = "600s"   # 10 minutes

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
  project = var.project_id

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

# Service account that Pub/Sub uses to invoke the event processor
resource "google_service_account" "event_processor_invoker_sa" {
  account_id   = "event-processor-invoker"
  display_name = "Pub/Sub → Event Processor invoker"
  project      = var.project_id
}

# Grant Pub/Sub permission to generate tokens for the invoker SA
resource "google_project_iam_member" "pubsub_token_creator" {
  project = var.project_id
  role    = "roles/iam.serviceAccountTokenCreator"
  member  = "serviceAccount:service-${data.google_project.project.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
}

data "google_project" "project" {
  project_id = var.project_id
}

# ---------------------------------------------------------------------------
# Cloud Tasks queues
# ---------------------------------------------------------------------------

resource "google_cloud_tasks_queue" "approval_escalations" {
  name     = "approval-escalations"
  project  = var.project_id
  location = var.region

  retry_config {
    max_attempts  = 3
    max_backoff   = "300s"
    min_backoff   = "10s"
    max_doublings = 3
  }

  rate_limits {
    max_dispatches_per_second = 10
    max_concurrent_dispatches = 5
  }

  depends_on = [google_project_service.enabled_services["cloudtasks.googleapis.com"]]
}

resource "google_cloud_tasks_queue" "remediation_execution" {
  name     = "remediation-execution"
  project  = var.project_id
  location = var.region

  retry_config {
    max_attempts  = 2
    max_backoff   = "60s"
    min_backoff   = "10s"
    max_doublings = 1
  }

  rate_limits {
    max_dispatches_per_second = 5
    max_concurrent_dispatches = 3
  }

  depends_on = [google_project_service.enabled_services["cloudtasks.googleapis.com"]]
}

resource "google_cloud_tasks_queue" "scc_remediation_tasks" {
  name     = "scc-remediation-tasks"
  project  = var.project_id
  location = var.region

  retry_config {
    max_attempts  = 3
    max_backoff   = "600s"
    min_backoff   = "30s"
    max_doublings = 2
  }

  rate_limits {
    max_dispatches_per_second = 10
    max_concurrent_dispatches = 10
  }

  depends_on = [google_project_service.enabled_services["cloudtasks.googleapis.com"]]
}

# ---------------------------------------------------------------------------
# Event processor Cloud Run service
# ---------------------------------------------------------------------------

resource "google_service_account" "event_processor_sa" {
  account_id   = "event-processor"
  display_name = "SCC Agent Event Processor"
  project      = var.project_id
}

resource "google_cloud_run_v2_service" "event_processor" {
  name     = "scc-event-processor"
  location = var.region
  project  = var.project_id

  ingress = "INGRESS_TRAFFIC_INTERNAL_ONLY"

  template {
    service_account = google_service_account.event_processor_sa.email

    containers {
      image = var.event_processor_image

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "NEO4J_URI"
        value = var.neo4j_bolt_uri
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
        value = var.scheduler_service_url
      }
      env {
        name  = "AGENT_SA_EMAIL"
        value = google_service_account.scc_agent_sa.email
      }
      env {
        name  = "CLOUD_TASKS_LOCATION"
        value = var.region
      }
      env {
        name  = "CLOUD_TASKS_QUEUE"
        value = google_cloud_tasks_queue.scc_remediation_tasks.name
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
      max_instance_count = 5
    }
  }

  depends_on = [
    google_project_service.enabled_services["run.googleapis.com"],
    google_secret_manager_secret_version.neo4j_password_version,
  ]
}

# Allow the Pub/Sub invoker SA to call the event processor
resource "google_cloud_run_v2_service_iam_member" "event_processor_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.event_processor.name
  role     = "roles/run.invoker"
  member   = "serviceAccount:${google_service_account.event_processor_invoker_sa.email}"
}

# Grant event processor SA access to Firestore and Cloud Tasks
resource "google_project_iam_member" "event_processor_firestore" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.event_processor_sa.email}"
}

resource "google_project_iam_member" "event_processor_tasks_enqueuer" {
  project = var.project_id
  role    = "roles/cloudtasks.enqueuer"
  member  = "serviceAccount:${google_service_account.event_processor_sa.email}"
}

resource "google_project_iam_member" "event_processor_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.event_processor_sa.email}"
}

# ---------------------------------------------------------------------------
# Firestore Database Configuration
# ---------------------------------------------------------------------------
resource "google_firestore_database" "database" {
  project     = var.project_id
  name        = "(default)"
  location_id = var.region
  type        = "FIRESTORE_NATIVE"
  depends_on  = [google_project_service.enabled_services["firestore.googleapis.com"]]
}
