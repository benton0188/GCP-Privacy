from google.cloud import bigquery
from google.cloud import securitycenter_v1beta1 as securitycenter

def check_cai_bigquery_instance():
    # Instantiate the BigQuery client
    client = bigquery.Client()

    # Retrieve the project ID, dataset ID, and table ID from the environment
    project_id = client.project
    dataset_id = "your-dataset-id"
    table_id = "your-table-id"

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

    # Retrieve the SCC project ID from the environment
    scc_project_id = client.project_path(project_id)

    # Retrieve the SCC source ID and finding ID from the environment or generate them as needed
    scc_source_id = "your-scc-source-id"
    scc_finding_id = "your-scc-finding-id"

    # Create the SCC finding name
    finding_name = f"organizations/{scc_project_id}/sources/{scc_source_id}/findings/{scc_finding_id}"

    # Create the SCC alert request with a severity of MEDIUM
    request = securitycenter.CreateFindingRequest(
        parent=f"organizations/{scc_project_id}",
        finding_id=scc_finding_id,
        finding={
            "name": finding_name,
            "state": securitycenter.Finding.State.ACTIVE,
            "severity": securitycenter.Finding.Severity.MEDIUM,
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

# Call the function to retrieve the necessary details
project_id, dataset_id, table_id, label, encryption_config, key_name, protection_level = check_cai_bigquery_instance()

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
    # Create an alert with a severity
    create_scc_alert(project_id, "your-scc-source-id", "your-scc-finding-id")
    print("SCC alert created.") 
   
