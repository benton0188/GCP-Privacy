from google.cloud import bigquery
from google.cloud import securitycenter_v1beta1 as securitycenter
from google.cloud import kms_v1
import uuid

def retrieve_cai_bigquery_table_details():
    # Instantiate the BigQuery client
    client = bigquery.Client()

    # Retrieve the project ID from the environment
    project_id = client.project

    # Fetch the CAI (Cloud Asset Inventory) data for the BigQuery tables in all regions
    cai_query = f"""
        SELECT
            resourceProperties.dataset_id,
            resourceProperties.table_id,
            assetTags.label,
            assetTags.encryptionConfiguration
        FROM
            `project_id`.region_us.INFORMATION_SCHEMA.TABLES
        WHERE
            table_type = 'BASE TABLE'
    """

    # Run the query to fetch the CAI data
    query_job = client.query(cai_query)
    results = query_job.result()

    # List to store the retrieved table details
    table_details = []

    # Extract the dataset ID, table ID, label, and encryption configuration from the query results
    for row in results:
        dataset_id = row.dataset_id
        table_id = row.table_id
        label = row.label
        encryption_config = row.encryptionConfiguration

        table_details.append((dataset_id, table_id, label, encryption_config))

    return project_id, table_details

def retrieve_kms_key_version(project_id, key_name):
    # Instantiate the KMS client
    client = kms_v1.KeyManagementServiceClient()

    # Construct the parent key resource name
    key_parent = client.crypto_key_path_path(project_id, "us", key_name)

    # List the key versions
    key_versions = client.list_crypto_key_versions(request={"parent": key_parent})

    # Fetch the latest key version
    latest_version = max(key_versions, key=lambda version: version.create_time)

    return latest_version

def get_key_protection_level(key_version):
    # Get the key protection level from the key version
    protection_level = key_version.protection_level

    return protection_level

# Retrieve the necessary details from CAI
project_id, table_details = retrieve_cai_bigquery_table_details()

# Check if any tables are found
if table_details:
    # Create an SCC source
    scc_source_id = create_scc_source(project_id)

    # Print the CAI details for each table
    for dataset_id, table_id, label, encryption_config in table_details:
        print("Project ID:", project_id)
        print("Dataset ID:", dataset_id)
        print("Table ID:", table_id)
        print("Label:", label)
        print("Encryption Configuration:", encryption_config)
        print("---")

        # Check the label and create SCC alert if applicable
        if label == "strictly_confidential":
            key_name = encryption_config.get("kmsKeyName")
            if key_name:
                # Retrieve the key version for the key name
                key_version = retrieve_kms_key_version(project_id, key_name)

                # Get the protection level from the key version
                protection_level = get_key_protection_level(key_version)

                if protection_level not in ["HSM", "External", "External_VPC"]:
                    # Create an SCC finding
                    scc_finding_id = create_scc_finding(project_id, scc_source_id)

                    # Create an SCC alert with a severity of MEDIUM
                    create_scc_alert(project_id, scc_source_id, scc_finding_id)

        # Iterate through the SCC findings for the BigQuery table
        iterate_scc_findings(project_id, scc_source_id)
else:
    print("No matching BigQuery tables found in CAI.")
