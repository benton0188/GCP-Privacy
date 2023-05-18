from google.cloud import bigquery

def check_cai_bigquery_instance(project_id, dataset_id, table_id):
    # Instantiate the BigQuery client
    client = bigquery.Client()

    # Get the BigQuery table reference
    table_ref = client.dataset(dataset_id).table(table_id)

    # Fetch the CAI (Cloud Asset Inventory) data for the BigQuery table
    table_cai = client.get_table(table_ref).to_api_repr().get("assetTags", {})

    # Retrieve the label and encryption configuration from the CAI data
    label = table_cai.get("label", {})
    encryption_config = table_cai.get("encryptionConfiguration", {})

    # Retrieve the key name from the encryption configuration
    key_name = encryption_config.get("kmsKeyName")

    # Fetch the KMS key reference
    if key_name:
        kms_client = client._http._auth_request.session._credentials.create_scoped(["https://www.googleapis.com/auth/cloud-platform"])
        kms_key = kms_client.get(key_name)

        # Retrieve the protection level of the key
        protection_level = kms_key.get("protectionLevel")

        return label, encryption_config, key_name, protection_level
    else:
        return label, encryption_config, None, None

# Provide the project ID, dataset ID, and table ID
project_id = "your-project-id"
dataset_id = "your-dataset-id"
table_id = "your-table-id"

# Call the function to retrieve the CAI, encryption details, and protection level
label, encryption_config, key_name, protection_level = check_cai_bigquery_instance(project_id, dataset_id, table_id)

# Print the results
print("Label:", label)
print("Encryption Configuration:", encryption_config)
print("Key Name:", key_name)
print("Protection Level:", protection_level)
