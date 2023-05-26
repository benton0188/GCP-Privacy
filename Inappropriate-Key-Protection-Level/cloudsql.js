const { google } = require('googleapis');
const { SecurityCenterClient } = require('@google-cloud/security-center');
const { KeyManagementServiceClient } = require('@google-cloud/kms');
const YOUR_ORGANIZATION_ID = 'YOUR_ORG_ID'; // Replace with your Organization ID
const keys = require('YOUR_SA_KEY'); // Replace with your SA with correct permissions

const jwtClient = new google.auth.JWT(
  keys.client_email,
  null,
  keys.private_key,
  ['https://www.googleapis.com/auth/cloud-platform'],
  null
);

async function createFinding(client, organizationId, sourceId, resourceId, findingId, category, projectId, keyName) {
  const [newFinding] = await client.createFinding({
    parent: `organizations/${organizationId}/sources/${sourceId}`,
    findingId: findingId,
    finding: {
      state: 'ACTIVE',
      severity: 'MEDIUM',
      findingClass: 'MISCONFIGURATION',
      resourceName: resourceId,
      category: category,
      eventTime: {
        seconds: Math.floor(Date.now() / 1000),
        nanos: (Date.now() % 1000) * 1e6,
      },
      sourceProperties: {
        projectId: { stringValue: projectId },
        keyName: { stringValue: keyName },
      },
    },
  });

  console.log('New finding created:', newFinding);
}

async function checkProtectionLevel(disk) {
  try {
    if (disk.diskEncryptionKey && disk.diskEncryptionKey.kmsKeyName) {
      const keyNameParts = disk.diskEncryptionKey.kmsKeyName.split('/cryptoKeyVersions/');
      const keyName = keyNameParts[0];
      console.log(`KMS key name: ${keyName}`);

      const kmsClient = new KeyManagementServiceClient();
      const [cryptoKey] = await kmsClient.getCryptoKey({ name: keyName });

      if (
        cryptoKey.primary.protectionLevel !== 'HSM' &&
        cryptoKey.primary.protectionLevel !== 'EXTERNAL' &&
        cryptoKey.primary.protectionLevel !== 'EXTERNAL_VPC'
      ) {
        return cryptoKey.primary.protectionLevel;
      }
    }
  } catch (error) {
    console.log('Error:', error);
  }
}

async function createSourceIfNotExists(client, organizationId) {
  try {
    const [sources] = await client.listSources({
      parent: `organizations/${organizationId}`,
    });

    const existingSource = sources.find(source => source.displayName === 'Privacy Misconfiguration');
    if (existingSource) {
      console.log('Existing source found:', existingSource);
      return existingSource;
    }

    const [newSource] = await client.createSource({
      parent: `organizations/${organizationId}`,
      source: {
        displayName: 'Privacy Misconfiguration',
        description: 'Persistent Disk key protection level violation.',
      },
    });
    console.log('New source created:', newSource);
    return newSource;
  } catch (error) {
    console.error('Failed to create or get source:', error);
    return null;
  }
}

async function renewToken() {
  return new Promise((resolve, reject) => {
    jwtClient.authorize((err, tokens) => {
      if (err) {
        reject(err);
      } else {
        console.log('Token renewed!');
        resolve(tokens);
      }
    });
  });
}

async function run() {
  try {
    const client = new SecurityCenterClient();

    const projectId = await google.auth.getProjectId();
    const compute = google.compute({ version: 'v1', auth: jwtClient });

    console.log(`Looking for disks in project: ${projectId}`);

    const zone = 'us-central1-a'; // specify the zone where you want to fetch the disks

    // Get all disks in the zone.
    const disksResponse = await compute.disks.list({ project: projectId, zone: zone });
    const disks = disksResponse.data.items || [];

    if (disks.length > 0) {
      for (const disk of disks) {
        console.log(`Found disk ${disk.name} in zone ${zone}`);

        const metadata = disk.labels;
        if (metadata && metadata['classification'] === 'strictly_confidential') {
          console.log(`Disk ${disk.name} has the 'strictly_confidential' label`);

          const protectionLevel = await checkProtectionLevel(disk);

          if (protectionLevel) {
            const source = await createSourceIfNotExists(client, YOUR_ORGANIZATION_ID);

            if (source) {
              const resourceId = disk.selfLink;
              let findingId = `strictConfidentialFinding${Date.now()}`;
              if (findingId.length > 32) {
                findingId = findingId.substring(0, 32);
              }
              console.log(`findingId: ${findingId}`);
              const category = 'PERSISTENT_DISK_KEY_PROTECTION_LEVEL';

              await createFinding(
                client,
                YOUR_ORGANIZATION_ID,
                source.name.split('/').pop(),
                resourceId,
                findingId,
                category,
                projectId,
                protectionLevel
              );
            }
          }
        } else {
          console.log(`Disk ${disk.name} does not have the 'strictly_confidential' label`);
        }
      }
    } else {
      console.log(`No disks found in zone ${zone}`);
    }
  } catch (error) {
    console.error('Error:', error);
    if (error.code === 7 && error.details === "Permission 'securitycenter.sources.update' denied") {
      console.log("Creating IAM policy for the service account...");
      try {
        await createIamPolicy();
        console.log("IAM policy created. Please rerun the script.");
      } catch (err) {
        console.error('Failed to create IAM policy:', err);
      }
    }
  }
}

async function createIamPolicy() {
  const projectId = await google.auth.getProjectId();
  const resourcemanager = google.resource('v1');

  const policy = {
    policy: {
      bindings: [
        {
          role: 'roles/securitycenter.findings.editor',
          members: [`serviceAccount:${keys.client_email}`],
        },
      ],
    },
  };

  await resourcemanager.projects.setIamPolicy({
    resource: `projects/${projectId}`,
    requestBody: policy,
  });
}

renewToken()
  .then(() => run())
  .catch(error => console.error('Error:', error));
