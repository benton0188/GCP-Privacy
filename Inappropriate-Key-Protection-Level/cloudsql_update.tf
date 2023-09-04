import json

def generate_terraform_template(project_id, customer_managed_encryption_key, protection_level):
  """Generates a Terraform template for the creation of a CloudSQL instance in a specific project with the label strictly_confidential and the customer managed encryption key with the protection level of Hardware.

  Args:
    project_id: The ID of the project in which to create the CloudSQL instance.
    customer_managed_encryption_key: The name of the customer managed encryption key to use for the CloudSQL instance.
    protection_level: The protection level of the customer managed encryption key.

  Returns:
    A string containing the Terraform template.
  """

  template = {
    "resource": "google_cloudsql_instance",
    "name": "my-cloudsql-instance",
    "project": project_id,
    "region": "us-central1",
    "database_version": "POSTGRES_14",
    "settings": {
      "tier": "db-f1-micro",
      "storage_auto_resize": True,
      "backup_configuration": {
        "enabled": True,
        "retention_period": "7"
      }
    },
    "labels": {
      "strictly_confidential": "true"
    },
    "encryption_config": {
      "kms_key_name": customer_managed_encryption_key,
      "kms_key_service_account": "serviceAccount:my-service-account@my-project.iam.gserviceaccount.com"
    },
    "protection_level": protection_level
  }

  return json.dumps(template, indent=4)

if __name__ == "__main__":
  project_id = "my-project"
  customer_managed_encryption_key = "projects/my-project/locations/global/keyRings/my-key-ring/cryptoKeys/my-encryption-key"
  protection_level = "HARDWARE"

  template = generate_terraform_template(project_id, customer_managed_encryption_key, protection_level)

  print(template)
