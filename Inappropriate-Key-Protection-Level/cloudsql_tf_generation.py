from google.oauth2 import service_account
from googleapiclient.discovery import build
from google.cloud import kms_v1
from google.cloud.kms_v1.types import CryptoKey, CryptoKeyVersionTemplate, ProtectionLevel

def get_cloudsql_instance_details(project_id, instance_name):
    credentials = service_account.Credentials.from_service_account_file(
        "/home/admin_/cureiamSA.json",
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    service = build('sqladmin', 'v1beta4', credentials=credentials)
    instances = service.instances()
    request = instances.get(project=project_id, instance=instance_name)
    response = request.execute()
    return response

def list_key_rings(project_id):
    client = kms_v1.KeyManagementServiceClient()
    parent = f"projects/{project_id}/locations/global"
    key_rings = client.list_key_rings(request={"parent": parent})
    return [key_ring.name.split('/')[-1] for key_ring in key_rings]

def create_crypto_key_with_hardware_protection(project_id, key_ring_name, key_name):
    client = kms_v1.KeyManagementServiceClient()
    parent = f"projects/{project_id}/locations/global/keyRings/{key_ring_name}"
    
    crypto_key = CryptoKey(
        purpose=CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT,
        version_template=CryptoKeyVersionTemplate(
            protection_level=ProtectionLevel.HSM,
        )
    )
    
    client.create_crypto_key(request={'parent': parent, 'crypto_key_id': key_name, 'crypto_key': crypto_key})

def generate_terraform_file(instance_details, key_ring_name, key_name):
    project_id = instance_details['project']
    instance_name = instance_details['name']
    database_version = instance_details['databaseVersion']
    region = instance_details['region']
    tier = instance_details['settings']['tier']

    terraform_content = f"""
provider "google" {{
  project     = "{project_id}"
}}

resource "google_sql_database_instance" "example" {{
  name             = "{instance_name}_update"
  region           = "{region}"
  database_version = "{database_version}"

  settings {{
    tier = "{tier}"
  
    disk_encryption_configuration {{
      kms_key_name = "projects/{project_id}/locations/global/keyRings/{key_ring_name}/cryptoKeys/{key_name}"
    }}

    labels = {{
      classification = "strictly_confidential"
    }}
  }}
}}
    """
    
    with open('cloudsql_update.tf', 'w') as f:
        f.write(terraform_content)

if __name__ == "__main__":
    project_id = "bq-cryptoshredding"  # Write code to get project ID
    instance_name = "postgres"  #Write code to get instance name

    # Fetch instance details
    instance_details = get_cloudsql_instance_details(project_id, instance_name)

    # Fetch available key rings
    key_rings = list_key_rings(project_id)

    if key_rings:
        key_ring_name = key_rings[0]
        new_key_name = "cloud_sql_hardware"  # Replace with your new key name
        
        # Create new key with hardware protection
        create_crypto_key_with_hardware_protection(project_id, key_ring_name, new_key_name)

        # Generate Terraform file
        generate_terraform_file(instance_details, key_ring_name, new_key_name)
    else:
        print("Could not find any key rings.")
