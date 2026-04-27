# --------------------------------------------------------------------------- #
# Neo4j — single Compute Engine VM, private IP only.
# The agent connects over the internal network via the instance's private IP.
# For a production deployment, use the GKE-based setup in terraform/neo4j.tf.
# --------------------------------------------------------------------------- #

resource "google_compute_address" "neo4j_internal" {
  name         = "neo4j-internal"
  project      = google_project.projects["infra"].project_id
  region       = var.region
  address_type = "INTERNAL"
  subnetwork   = google_compute_subnetwork.neo4j_subnet.id
  depends_on   = [google_project_service.infra_services]
}

resource "google_compute_network" "neo4j_vpc" {
  name                    = "neo4j-vpc"
  project                 = google_project.projects["infra"].project_id
  auto_create_subnetworks = false
  depends_on              = [google_project_service.infra_services]
}

resource "google_compute_subnetwork" "neo4j_subnet" {
  name          = "neo4j-subnet"
  ip_cidr_range = "10.20.0.0/24"
  region        = var.region
  network       = google_compute_network.neo4j_vpc.id
  project       = google_project.projects["infra"].project_id
}

# Allow the agent SA and IAP tunnels to reach Neo4j on port 7687 (Bolt)
resource "google_compute_firewall" "allow_bolt" {
  name    = "allow-neo4j-bolt"
  network = google_compute_network.neo4j_vpc.name
  project = google_project.projects["infra"].project_id

  allow {
    protocol = "tcp"
    ports    = ["7687"]
  }

  # Restrict to the subnet range + IAP source range for tunnel access
  source_ranges = ["10.20.0.0/24", "35.235.240.0/20"]
}

resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "allow-iap-ssh-neo4j"
  network = google_compute_network.neo4j_vpc.name
  project = google_project.projects["infra"].project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["35.235.240.0/20"] # IAP only — no public SSH
}

resource "google_compute_instance" "neo4j" {
  name         = "neo4j-demo"
  machine_type = "e2-standard-2" # 2 vCPU / 8 GB — sufficient for demo graph
  zone         = "${var.region}-a"
  project      = google_project.projects["infra"].project_id

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 50 # GB — enough for a demo asset graph
      type  = "pd-ssd"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.neo4j_subnet.id
    network_ip = google_compute_address.neo4j_internal.address
    # No access_config block — no public IP
  }

  service_account {
    email  = google_service_account.agent_sa.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    enable-oslogin = "TRUE"
    # Startup script: install Neo4j 5 and set the password from Secret Manager
    startup-script = <<-SCRIPT
      #!/bin/bash
      set -euo pipefail

      # Install Java (Neo4j 5 requires Java 17)
      apt-get update -qq
      apt-get install -y -qq openjdk-17-jre-headless gnupg curl

      # Add Neo4j apt repo
      curl -fsSL https://debian.neo4j.com/neotechnology.gpg.key | gpg --dearmor -o /usr/share/keyrings/neo4j.gpg
      echo "deb [signed-by=/usr/share/keyrings/neo4j.gpg] https://debian.neo4j.com stable 5" \
        > /etc/apt/sources.list.d/neo4j.list
      apt-get update -qq
      apt-get install -y -qq neo4j

      # Fetch the password from Secret Manager
      NEO4J_PASS=$(curl -sS \
        -H "Authorization: Bearer $(curl -sS -H 'Metadata-Flavor: Google' \
          http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token \
          | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')" \
        "https://secretmanager.googleapis.com/v1/${google_secret_manager_secret.neo4j_password.name}/versions/latest:access" \
        | python3 -c 'import sys,json,base64; print(base64.b64decode(json.load(sys.stdin)["payload"]["data"]).decode())')

      # Configure Neo4j
      neo4j-admin dbms set-initial-password "$NEO4J_PASS"

      # Listen on all interfaces so the agent can connect over the internal subnet
      sed -i 's/#server.bolt.listen_address=:7687/server.bolt.listen_address=0.0.0.0:7687/' \
        /etc/neo4j/neo4j.conf
      sed -i 's/#server.bolt.advertised_address=:7687/server.bolt.advertised_address=:7687/' \
        /etc/neo4j/neo4j.conf

      # Disable browser/HTTP interface (not needed in demo)
      echo "server.http.enabled=false" >> /etc/neo4j/neo4j.conf
      echo "server.https.enabled=false" >> /etc/neo4j/neo4j.conf

      systemctl enable neo4j
      systemctl start neo4j

      echo "Neo4j startup complete" > /var/log/neo4j-startup-done
    SCRIPT
  }

  labels = {
    component = "neo4j"
    env       = "demo"
  }

  tags = ["neo4j"]

  depends_on = [
    google_project_service.infra_services,
    google_secret_manager_secret_version.neo4j_password,
  ]
}
