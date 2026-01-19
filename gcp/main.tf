provider "google" {
  project = var.project_id
  region  = var.region
}

# ==============================================================================
# 1. NETWORKING (Critical for AlloyDB & Redis)
# ==============================================================================
resource "google_compute_network" "vpc_network" {
  name                    = "vuln-mgmt-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "subnet" {
  name          = "vuln-mgmt-subnet"
  ip_cidr_range = "10.0.0.0/24"
  region        = var.region
  network       = google_compute_network.vpc_network.id
}

# Cloud Router required for NAT
resource "google_compute_router" "router" {
  name    = "alloydb-router"
  region  = var.region
  network = google_compute_network.vpc_network.id
}

# Cloud NAT for outbound internet access
resource "google_compute_router_nat" "nat" {
  name                               = "alloydb-nat"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
}

# Reserve IP range for Private Service Access (AlloyDB & Redis)
resource "google_compute_global_address" "private_ip_range" {
  name          = "private-ip-block"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc_network.id
}

# Establish the VPC Peering connection
resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.vpc_network.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]
}

# ==============================================================================
# 2. ALLOYDB (The Serving Layer)
# ==============================================================================
resource "google_alloydb_cluster" "vuln_cluster" {
  cluster_id          = "vuln-consolidation-cluster"
  location            = var.region
  deletion_protection = false
  network_config {
    network = google_compute_network.vpc_network.id
  }

  initial_user {
    user     = "postgres"
    password = var.db_password
  }

  # Disable continuous backup for dev environment
  continuous_backup_config {
    enabled = false
  }

  # Disable automated backup for dev environment
  automated_backup_policy {
    enabled = false
  }

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

resource "google_alloydb_instance" "vuln_primary_instance" {
  cluster       = google_alloydb_cluster.vuln_cluster.name
  instance_id   = "vuln-primary-instance"
  instance_type = "PRIMARY"

  # 4 vCPU, 32GB RAM is a good starting point for our volumes in real life
  # For our PoCs, we'll go with 2 vCPU, 16GB RAM to start with
  machine_config {
    cpu_count = 2
  }

  # Ensure single availability zone deployment
  availability_type = "ZONAL"
}

# Create a service account for the VM
resource "google_service_account" "vm_service_account" {
  account_id   = "alloydb-vm-sa"
  display_name = "Service Account for AlloyDB VM"
}

# Grant the service account necessary permissions for AlloyDB
resource "google_project_iam_member" "alloydb_client" {
  project = var.project_id
  role    = "roles/alloydb.client"
  member  = "serviceAccount:${google_service_account.vm_service_account.email}"
}

# Grant BigQuery Data Editor permissions to allow adding and removing data
resource "google_project_iam_member" "bq_data_editor" {
  project = var.project_id
  role    = "roles/bigquery.dataEditor"
  member  = "serviceAccount:${google_service_account.vm_service_account.email}"
}

# Grant BigQuery Job User permissions to allow running queries
resource "google_project_iam_member" "bq_job_user" {
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.vm_service_account.email}"
}

# Create the VM instance
resource "google_compute_instance" "alloydb_vm" {
  name         = "alloydb-access-vm"
  machine_type = "e2-small"
  zone         = "${var.region}-a" # Adjust zone suffix as needed

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-12"
      size  = 20
      type  = "pd-standard"
    }
  }

  network_interface {
    network    = google_compute_network.vpc_network.id
    subnetwork = google_compute_subnetwork.subnet.id

    # No external IP for better security - access via IAP
    # If you need external IP, uncomment the following:
    # access_config {}
  }

  service_account {
    email  = google_service_account.vm_service_account.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    enable-oslogin = "TRUE"
  }

  # Install PostgreSQL client on startup
  metadata_startup_script = <<-EOF
    #!/bin/bash
    apt-get update
    apt-get install -y postgresql-client
  EOF

  tags = ["alloydb-client"]

  depends_on = [
    google_compute_subnetwork.subnet,
    google_service_account.vm_service_account
  ]
}

# Firewall rule to allow IAP SSH access
resource "google_compute_firewall" "allow_iap_ssh" {
  name    = "allow-iap-ssh"
  network = google_compute_network.vpc_network.id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  # IAP IP range
  source_ranges = ["35.235.240.0/20"]

  target_tags = ["alloydb-client"]
}

# Output the connection command
output "ssh_command" {
  value       = "gcloud compute ssh ${google_compute_instance.alloydb_vm.name} --zone=${google_compute_instance.alloydb_vm.zone} --tunnel-through-iap"
  description = "Command to SSH into the VM"
}

output "alloydb_connection_command" {
  value       = "psql -h ${google_alloydb_cluster.vuln_cluster.name} -U postgres -d postgres"
  description = "Command to connect to AlloyDB from the VM (run after SSH)"
  sensitive   = false
}


# ==============================================================================
# 3. BIGQUERY (The Historical Archive)
# ==============================================================================
resource "google_bigquery_dataset" "vuln_archive" {
  dataset_id    = "vulnerability_archive"
  friendly_name = "Scan History"
  description   = "Raw immutable scan logs retained for 6 months"
  location      = var.region
  # default_table_expiration_ms = 15778800000 # ~6 months in ms
  default_table_expiration_ms = 2592000000 # 30 days in ms
}

resource "google_bigquery_table" "scan_logs" {
  dataset_id          = google_bigquery_dataset.vuln_archive.dataset_id
  table_id            = "raw_scan_logs"
  deletion_protection = false

  # Partition by Ingestion Time for efficient cost management
  time_partitioning {
    type = "DAY"
  }

  schema = <<EOF
[
  { "name": "asset_id", "type": "STRING", "mode": "REQUIRED" },
  { "name": "scan_date", "type": "TIMESTAMP", "mode": "REQUIRED" },
  { "name": "cve_id", "type": "STRING", "mode": "REQUIRED" },
  { "name": "findings_json", "type": "JSON", "mode": "NULLABLE" },
  { "name": "ingestion_time", "type": "TIMESTAMP", "mode": "REQUIRED" }
]
EOF
}

# # GCS Bucket for Dataflow Temp/Staging
# resource "google_storage_bucket" "dataflow_bucket" {
#   name          = "${var.project_id}-dataflow-temp"
#   location      = var.region
#   force_destroy = false
# }

# # Service Account for the Dataflow Worker
# resource "google_service_account" "dataflow_sa" {
#   account_id   = "vuln-dataflow-worker"
#   display_name = "Vulnerability Dataflow Service Account"
# }

# # Grant Permissions to Dataflow SA
# resource "google_project_iam_member" "df_worker" {
#   project = var.project_id
#   role    = "roles/dataflow.worker"
#   member  = "serviceAccount:${google_service_account.dataflow_sa.email}"
# }

# resource "google_project_iam_member" "df_bq_editor" {
#   project = var.project_id
#   role    = "roles/bigquery.dataEditor"
#   member  = "serviceAccount:${google_service_account.dataflow_sa.email}"
# }

# resource "google_project_iam_member" "df_alloydb_client" {
#   project = var.project_id
#   role    = "roles/alloydb.client"
#   member  = "serviceAccount:${google_service_account.dataflow_sa.email}"
# }
