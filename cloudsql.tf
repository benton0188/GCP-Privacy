
provider "google" {
  project     = "bq-cryptoshredding"
}

resource "google_sql_database_instance" "example" {
  name             = "postgres_update"
  region           = "us-central1"
  database_version = "POSTGRES_14"

  settings {
    tier = "db-custom-4-26624"
  
    disk_encryption_configuration {
      kms_key_name = "projects/bq-cryptoshredding/locations/global/keyRings/bq-cryptoshredding/cryptoKeys/cloud_sql_hardware_updated-key"
    }

    labels = {
      classification = "strictly_confidential"
    }
  }
}
    