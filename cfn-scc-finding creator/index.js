/**
 * Triggered from a message on a Cloud Pub/Sub topic.
 *
 * @param {!Object} event Event payload.
 * @param {!Object} context Metadata for the event.
 * 
 * 
 */
const { SecurityCenterClient } = require('@google-cloud/security-center');
const client = new SecurityCenterClient();

async function createFinding(resource) {
  const [newFinding] = await client.createFinding({
    parent: 'organizations/[organization_id]/sources/[source_id]',
    findingId: 'OwRoleAdd' + Date.now(),
    finding: {
      state: 'ACTIVE',
      severity: 'MEDIUM',
      // Resource the finding is associated with.  This is an
      // example any resource identifier can be used.
      resourceName: resource,
      // A free-form category.
      category: 'INTERNAL_POLICY_VIOLATION',
      // The time associated with discovering the issue.
      eventTime: {
        seconds: Math.floor(Date.now() / 1000),
        nanos: (Date.now() % 1000) * 1e6,
        externalUri: 'https://cloud.google.com/iam/docs'
      },
      sourceProperties: {
        s_value: { stringValue: 'string_example' },
        n_value: { numberValue: 1234 },
      },
    }, 
  });
  console.log('New finding created: %j', newFinding);
}


exports.createSccFinding = (event, context) => {
  //const message = event.data
  //? Buffer.from(event.data, 'base64').toString()
  //: 'Hello, World';
  console.log('--- Executing cnf-scc-finding-creator on aggregated log ---');
  let strMessage = Buffer.from(event.data, 'base64').toString();
  let message = JSON.parse(strMessage);
  let payload = message.protoPayload;
  try {
    let bd = payload.serviceData.policyDelta.bindingDeltas;
    console.log('All data present in message');
    bd.forEach(d => {
      if(d.action=='ADD' && d.role=='roles/owner' || d.role=='roles/editor' || d.role=='role/viewer') {
        console.log('-----> Creating finding in SCC');
        createFinding(payload.resourceName);
      }    
    });
  } catch (e) {
    console.error("Something wrong happened.", e);
  }
  //createFinding();
  //message.protoPayload.serviceData.policyDelta.bindingDeltas.forEach(delta => {
  //  console.log("--- Delta is ");
  //  console.log(delta);
  //  if(delta.action==="ADD") {
  //    console.log("--- Found added role binding for role " + delta.role + ' member ' + delta.member);
  //   
  //  }
  //});

};
