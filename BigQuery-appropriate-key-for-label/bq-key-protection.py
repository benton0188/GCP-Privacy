from google.cloud import bigquery
from google.cloud import securitycenter_v1beta1 as securitycenter

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

        return project_id, dataset_id, table_id, label, encryption_config, key_name, protection_level
    else:
        return project_id, dataset_id, table_id, label, encryption_config, None, None

def create_scc_alert(project_id, source_id, finding_id):
    # Instantiate the SCC client
    client = securitycenter.SecurityCenterClient()

    # Create the SCC finding name
    finding_name = f"organizations/{project_id}/sources/{source_id}/findings/{finding_id}"

    # Create the SCC alert request
    request = securitycenter.CreateFindingRequest(
        parent=f"organizations/{project_id}",
        finding_id=finding_id,
        finding={
            "name": finding_name,
            "state": securitycenter.Finding.State.ACTIVE,
            "source_properties": {
                "status": "open"
            },
            "security_marks": {
                "marks": {
                    "alert": "true"
                }
            }
        }
    )

    # Send the alert request to SCC
    response = client.create_finding(request)

    return response

# Provide the project ID, dataset ID, and table ID
project_id = "your-project-id"
dataset_id = "your-dataset-id"
table_id = "your-table-id"

# Call the function to retrieve the project ID, dataset ID, table ID, label, encryption details, and protection level
project_id, dataset_id, table_id, label, encryption_config, key_name, protection_level = check_cai_bigquery_instance(project_id, dataset_id, table_id)

# Print the results
print("Project ID:", project_id)
print("Dataset ID:", dataset_id)
print("Table ID:", table_id)
print("Label:", label)
print("Encryption Configuration:", encryption_config)
print("Key Name:", key_name)
print("Protection Level:", protection_level)

# Check the label and protection level criteria
if label == "Strictly Confidential" and protection_level not in ["HSM", "External", "External_VPC"]:
    # Provide the SCC project ID, source ID, and finding ID
    scc_project_id = "your-scc-project-id"
    scc_source_id = "your-scc-source-id"
    scc_finding_id = "your-scc-finding-id"

    # Create an alert in SCC
    response = create_scc_alert(scc_project_id,
