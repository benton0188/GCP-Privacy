import os
import google
from google.cloud import asset_v1, bigquery, kms_v1, securitycenter_v1

# Get the project ID
project_id = os.environ['GOOGLE_CLOUD_PROJECT']

# Get the organization ID
organization_id = google.cloud.environment.organization_id

# Get the Dataset IDs
dataset_ids = []
for asset in asset_v1.AssetServiceClient().list_assets(parent=organization_id).assets:
    dataset_ids.append(asset.resource.dataset_id)

# Get the Table IDs
table_ids = []
for asset in asset_v1.AssetServiceClient().list_assets(parent=organization_id).assets:
    table_ids.append(asset.resource.table_id)

# Get the key names
key_names = []
for asset in asset_v1.AssetServiceClient().list_assets(parent=organization_id).assets:
    key_names.append(asset.resource.name)

# Initialize the BigQuery client
bq_client = bigquery.Client()

# Initialize the KMS client
kms_client = kms_v1.KeyManagementServiceClient()

# Initialize the Security Center client
scc_client = securitycenter_v1.SecurityCenterClient()

# Go through each Dataset ID
for dataset_id in dataset_ids:

    # Get the tables in the dataset
    dataset_ref = bq_client.dataset(dataset_id, project=project_id)
    tables = bq_client.list_tables(dataset_ref)

    # Go through each Table ID
    for table_id in table_ids:

        # Get the table reference
        table_ref = dataset_ref.table(table_id)

        # Get the full table
        full_table = bq_client.get_table(table_ref)

        # If the label "strictly_confidential" is present
        if 'strictly_confidential' in full_table.labels:

            # Check the encryption configuration
            if full_table.encryption_configuration:

                # Get the key name
                kms_key_name = full_table.encryption_configuration.kms_key_name

                # Get the key
                crypto_key = kms_client.get_crypto_key(request={'name': kms_key_name})

                # Get the protection level of the key
                protection_level = crypto_key.purpose

                # If the protection level is not HSM, External or External_VPC
                if protection_level not in [kms_v1.CryptoKey.CryptoKeyPurpose.HSM_ENCRYPT_DECRYPT,
                                              kms_v1.CryptoKey.CryptoKeyPurpose.EXTERNAL_ENCRYPT_DECRYPT]:

                    # Create an alert in SCC
                    finding = securitycenter_v1.Finding()
                    finding.parent = securitycenter_v1.SecurityCenterClient.organization_path(
                        security_center_org_id)
                    finding.category = "INAPPROPRIATE_DATA_PROTECTION_LEVEL"
                    finding.source_properties = {
                        "projectId": project_id,
                        "datasetId": dataset_id,
                        "tableId": table_id,
                        "kmsKeyName": kms_key_name,
                        "cryptoKeyPurpose": protection_level,
                    }
                    scc_client.create_finding(parent=finding.parent, finding_id='finding_id', finding=finding)

# To run the code successfully, you need to:

# 1. Install the `google-api-python-client` library.
# 2. Set the following environment variable:
#     * GOOGLE_CLOUD_PROJECT
# 3. Run the code in a Python interpreter.
