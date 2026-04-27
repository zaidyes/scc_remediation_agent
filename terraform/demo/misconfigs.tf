# --------------------------------------------------------------------------- #
# Intentionally misconfigured resources — each one triggers a specific SCC
# finding category so the agent has real findings to remediate.
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# 1. Public GCS bucket  →  PUBLIC_BUCKET_ACL / BUCKET_POLICY_ONLY_DISABLED
# --------------------------------------------------------------------------- #
resource "google_storage_bucket" "public_bucket" {
  name                        = "demo-public-${random_id.suffix.hex}"
  location                    = var.region
  project                     = google_project.projects["data"].project_id
  force_destroy               = true
  uniform_bucket_level_access = false # intentionally disabled

  depends_on = [google_project_service.data_services]
}

resource "google_storage_bucket_iam_member" "public_read" {
  bucket = google_storage_bucket.public_bucket.name
  role   = "roles/storage.objectViewer"
  member = "allUsers" # makes it public — triggers PUBLIC_BUCKET_ACL
}

# --------------------------------------------------------------------------- #
# 2. Open SSH firewall rule  →  OPEN_SSH_PORT / OPEN_FIREWALL
# --------------------------------------------------------------------------- #
resource "google_compute_network" "demo_vpc" {
  name                    = "demo-vpc"
  project                 = google_project.projects["web"].project_id
  auto_create_subnetworks = false
  depends_on              = [google_project_service.web_services]
}

resource "google_compute_subnetwork" "demo_subnet" {
  name          = "demo-subnet"
  ip_cidr_range = "10.10.0.0/24"
  region        = var.region
  network       = google_compute_network.demo_vpc.id
  project       = google_project.projects["web"].project_id
}

resource "google_compute_firewall" "open_ssh" {
  name    = "demo-allow-ssh-world"
  network = google_compute_network.demo_vpc.name
  project = google_project.projects["web"].project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"] # triggers OPEN_SSH_PORT
}

resource "google_compute_firewall" "open_rdp" {
  name    = "demo-allow-rdp-world"
  network = google_compute_network.demo_vpc.name
  project = google_project.projects["web"].project_id

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }
  source_ranges = ["0.0.0.0/0"] # triggers OPEN_RDP_PORT
}

# --------------------------------------------------------------------------- #
# 3. VM with public IP and no OS Config agent  →  PUBLIC_IP_ADDRESS
# --------------------------------------------------------------------------- #
resource "google_compute_instance" "demo_vm" {
  name         = "demo-web-vm"
  machine_type = "e2-micro"
  zone         = "${var.region}-a"
  project      = google_project.projects["web"].project_id

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.demo_subnet.id
    access_config {} # ephemeral public IP — triggers PUBLIC_IP_ADDRESS
  }

  # No OS Config metadata — intentionally omitted to trigger OS patch findings
  metadata = {
    enable-oslogin = "TRUE"
  }

  labels = {
    env  = "demo"
    team = "web"
  }

  depends_on = [google_project_service.web_services]
}

# --------------------------------------------------------------------------- #
# 4. Over-permissioned service account  →  ADMIN_SERVICE_ACCOUNT
# --------------------------------------------------------------------------- #
resource "google_service_account" "overpermissioned_sa" {
  account_id   = "demo-overperm-sa"
  display_name = "Demo Over-Permissioned SA"
  project      = google_project.projects["data"].project_id
  depends_on   = [google_project_service.data_services]
}

resource "google_project_iam_member" "sa_owner" {
  project = google_project.projects["data"].project_id
  role    = "roles/owner" # triggers ADMIN_SERVICE_ACCOUNT
  member  = "serviceAccount:${google_service_account.overpermissioned_sa.email}"
}

# --------------------------------------------------------------------------- #
# 5. Service account key  →  SERVICE_ACCOUNT_KEY_CREATED
# --------------------------------------------------------------------------- #
resource "google_service_account_key" "demo_key" {
  service_account_id = google_service_account.overpermissioned_sa.name
  # Key creation itself triggers SERVICE_ACCOUNT_KEY_CREATED in SCC
}

# Discard the key material — we only need the finding, not the key
resource "google_secret_manager_secret" "discarded_sa_key" {
  secret_id = "demo-discarded-sa-key"
  project   = google_project.projects["infra"].project_id
  replication { auto {} }
  depends_on = [google_project_service.infra_services]
}

resource "google_secret_manager_secret_version" "discarded_sa_key" {
  secret      = google_secret_manager_secret.discarded_sa_key.id
  secret_data = google_service_account_key.demo_key.private_key
}
