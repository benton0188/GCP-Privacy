package com.example;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import com.example.IamGrantRemediator.PubSubMessage;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.services.cloudresourcemanager.v3.CloudResourceManager;
import com.google.api.services.cloudresourcemanager.v3.model.Binding;
import com.google.api.services.cloudresourcemanager.v3.model.GetIamPolicyRequest;
import com.google.api.services.cloudresourcemanager.v3.model.Policy;
import com.google.api.services.cloudresourcemanager.v3.model.SetIamPolicyRequest;
import com.google.api.services.iam.v1.IamScopes;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.cloud.functions.BackgroundFunction;
import com.google.cloud.functions.Context;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class IamGrantRemediator implements BackgroundFunction<PubSubMessage> {
  private static final Logger logger = Logger.getLogger(IamGrantRemediator.class.getName());

  @Override
  public void accept(PubSubMessage message, Context context) {
    logger.info("--- Executing IamGrantRemediator on aggregated log ---");
    String strMessage = message.data != null
        ? new String(Base64.getDecoder().decode(message.data))
        : null;

    if (strMessage == null) {
      logger.warning("No data in message !");
      return;
    }
    ;

    Gson gson = new Gson();
    JsonObject eventData = gson.fromJson(strMessage, JsonObject.class);
    JsonObject payload = eventData.getAsJsonObject("protoPayload");
    
    if ("SetIamPolicy".equals(payload.getAsJsonPrimitive("methodName").getAsString())) {
      JsonArray deltas = payload.getAsJsonObject("serviceData").getAsJsonObject("policyDelta").getAsJsonArray("bindingDeltas");
      for (JsonElement delta : deltas) {
        logger.info("Delta object is: " + delta);
        String action = delta.getAsJsonObject().getAsJsonPrimitive("action").getAsString();
        String role =  delta.getAsJsonObject().getAsJsonPrimitive("role").getAsString();
        String member =  delta.getAsJsonObject().getAsJsonPrimitive("member").getAsString();
        String project = payload.getAsJsonPrimitive("resourceName").getAsString();
        if("ADD".equals(action) && "roles/owner".equals(role)){
          logger.info("Illegal grant detected starting remediation: " + member);
          CloudResourceManager service = null;
          try {
            service = initializeService();
          } catch (IOException | GeneralSecurityException e) {
            logger.warning("Unable to initialize service: \n" + e.toString());
            return;
          }
          Policy p = this.getPolicy(service, project);
          this.removeMember(p, role, member);
          this.setPolicy(service, project, p);
        }
      }
    }

      /*
       * message.protoPayload.serviceData.policyDelta.bindingDeltas.forEach(delta => {
       * console.log("--- Delta is ");
       * console.log(delta);
       * if(delta.action==="ADD") {
       * console.log("--- Found added role binding for role " + delta.role + ' member
       * ' + delta.member);
       * }
       * });
       */
  }

// Removes member from a role; removes binding if binding contains 0 members.
private  void removeMember(Policy policy, String role, String member) {
  // policy = service.Projects.GetIAmPolicy(new GetIamPolicyRequest(), your-project-id).Execute();

  List<Binding> bindings = policy.getBindings();
  Binding binding = null;
  for (Binding b : bindings) {
    if (b.getRole().equals(role)) {
      binding = b;
    }
  }
  if (binding.getMembers().contains(member)) {
    binding.getMembers().remove(member);
    System.out.println("Member " + member + " removed from " + role);
    if (binding.getMembers().isEmpty()) {
      policy.getBindings().remove(binding);
    }
    return;
  }

  System.out.println("Role not found in policy; member not removed");
  return;
}

private Policy getPolicy(CloudResourceManager service, String projectId) {
  // projectId = "my-project-id"

  Policy policy = null;

  try {
    GetIamPolicyRequest request = new GetIamPolicyRequest();
    policy = service.projects().getIamPolicy(projectId, request).execute();
    logger.info("Policy retrieved: " + policy.toString());
    return policy;
  } catch (IOException e) {
    logger.warning("Unable to get policy: \n" + e.toString());
    return policy;
  }
}

private void setPolicy(CloudResourceManager crmService, String projectId, Policy policy) {
  // Sets the project's policy by calling the
  // Cloud Resource Manager Projects API.
  try {
    SetIamPolicyRequest request = new SetIamPolicyRequest();
    request.setPolicy(policy);
    crmService.projects().setIamPolicy(projectId, request).execute();
  } catch (IOException e) {
    System.out.println("Unable to set policy: \n" + e.getMessage() + e.getStackTrace());
  }
}

public static CloudResourceManager initializeService()
      throws IOException, GeneralSecurityException {
    // Use the Application Default Credentials strategy for authentication. For more info, see:
    // https://cloud.google.com/docs/authentication/production#finding_credentials_automatically
    GoogleCredentials credential =
        GoogleCredentials.getApplicationDefault()
            .createScoped(Collections.singleton(IamScopes.CLOUD_PLATFORM));

    // Creates the Cloud Resource Manager service object.
    CloudResourceManager service =
        new CloudResourceManager.Builder(
                GoogleNetHttpTransport.newTrustedTransport(),
                JacksonFactory.getDefaultInstance(),
                new HttpCredentialsAdapter(credential))
            .setApplicationName("iam-quickstart")
            .build();
    return service;
  }

  public static class PubSubMessage {
    String data;
    Map<String, String> attributes;
    String messageId;
    String publishTime;
  }
}
