const { BigQuery } = require('@google-cloud/bigquery');
const { SecurityCenterClient } = require('@google-cloud/security-center');
const { KeyManagementServiceClient } = require('@google-cloud/kms');
const { google } = require('googleapis');

const YOUR_ORGANIZATION_ID = 'YOUR_ORG_ID'; // Update with your Organization ID

function generateFindingId(datasetId) {
  const randomString = Math.random().toString(36).substring(2, 10); // Generate a random string
  const sanitizedDatasetId = datasetId.replace(/[^a-z0-9]/gi, ''); // Remove non-alphanumeric characters from the dataset ID
  const findingId = `${sanitizedDatasetId}${randomString}`; // Combine the dataset ID and random string

  return findingId;
}

async function getProjectDetails() {
  const auth = await google.auth.getClient({
    scopes: ['https://www.googleapis.com/auth/cloud-platform'],
  });
  const project = await google.auth.getProjectId();
  const cloudresourcemanager = google.cloudresourcemanager('v1');
  const { data } = await cloudresourcemanager.projects.get({
    auth: auth,
    projectId: project,
  });

  return {
    YOUR_PROJECT_ID: data.projectId,
    YOUR_PROJECT_NUMBER: data.projectNumber,
  };
}

async function createFinding(client, organizationId, sourceId, resource, findingId, category) {
  const [newFinding] = await client.createFinding({
    parent: `organizations/${organizationId}/sources/${sourceId}`,
    findingId: findingId,
    finding: {
      state: 'ACTIVE',
      severity: 'MEDIUM',
      findingClass: "MISCONFIGURATION",
      resourceName: resource,
      category: 'BIGQUERY_DATASET_LOW_PROTECTION_LEVEL',
      eventTime: {
        seconds: Math.floor(Date.now() / 1000),
        nanos: (Date.now() % 1000) * 1e6,
      },
    },
  });

  console.log('New finding created:', newFinding);
}

async function checkCAI() {
  try {
    const bigquery = new BigQuery();
    const client = new SecurityCenterClient();
    const kmsClient = new KeyManagementServiceClient();
    const projectDetails = await getProjectDetails();

    console.log('Project details:', projectDetails);

    const [datasets] = await bigquery.getDatasets();
    for (const dataset of datasets) {
      const [metadata] = await dataset.getMetadata();
      if ('labels' in metadata && 'classification' in metadata.labels && metadata.labels.classification === 'YOUR_CLASSIFICATION_LABELS') {  //eg 'strictly_confidential'//
        if (metadata.defaultEncryptionConfiguration && metadata.defaultEncryptionConfiguration.kmsKeyName) {
          const keyName = metadata.defaultEncryptionConfiguration.kmsKeyName;
          const [cryptoKey] = await kmsClient.getCryptoKey({ name: keyName });
          if (cryptoKey.primary.protectionLevel !== 'HSM' && cryptoKey.primary.protectionLevel !== 'EXTERNAL' && cryptoKey.primary.protectionLevel !== 'EXTERNAL_VPC'){  // What your internal policy states //
            const [source] = await client.createSource({
              parent: `organizations/${YOUR_ORGANIZATION_ID}`,
              source: {
                displayName: 'Privacy Misconfiguration',
                description: 'BigQuery Table low protection level.',
              },
            });
            const resourceId = metadata.datasetReference.datasetId;
            const findingId = generateFindingId(dataset.id);
            const category = 'INTERNAL_POLICY_VIOLATION';

            console.log('Resource name:', resourceId);
            console.log('Finding Id:', findingId);
            console.log('Resource Id:', resourceId);

            await createFinding(client, YOUR_ORGANIZATION_ID, source.name.split('/').pop(), resourceId, findingId, category);
          }
        }
      }
    }
  } catch (error) {
    console.error('Error during checkCAI:', error);
  }
}

checkCAI();
