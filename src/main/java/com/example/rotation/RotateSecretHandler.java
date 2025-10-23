package com.example.rotation;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.PutSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.*;

import java.util.Map;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.UUID;


public class RotateSecretHandler implements RequestHandler<Map<String, Object>, String> {

    private final SecretsManagerClient client = SecretsManagerClient.create();

    @Override
    public String handleRequest(Map<String, Object> event, Context context) {
        String step = (String) event.get("Step");
        String secretId = (String) event.get("SecretId");
        String token = (String) event.get("ClientRequestToken");

        context.getLogger().log("Rotation step = " + step + ", secretId = " + secretId + "\n");

        switch (step) {
            case "createSecret":
                try {
                    return createSecret(secretId, token, context);
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            case "setSecret":
                return setSecret(secretId, token, context);
            case "testSecret":
                return testSecret(secretId, token, context);
            case "finishSecret":
                return finishSecret(secretId, token, context);
            default:
                throw new IllegalArgumentException("Unknown step " + step);
        }
    }

    private String createSecret(String secretId, String token, Context context) throws Exception {
        DescribeSecretResponse describe = client.describeSecret(
                DescribeSecretRequest.builder().secretId(secretId).build());

        // ✅ Case 1: Pending version already registered in metadata
        if (describe.versionIdsToStages().containsKey(token)) {
            context.getLogger().log("Pending version metadata found, validating...\n");
            try {
                // Try to fetch the AWSPENDING secret value
                GetSecretValueResponse pending = client.getSecretValue(
                        GetSecretValueRequest.builder()
                                .secretId(secretId)
                                .versionId(token)
                                .versionStage("AWSPENDING")
                                .build());
                String pendingSecret = pending.secretString();

                // Validate it
                if (testSecretWithExternalSystem(pendingSecret, context)) {
                    context.getLogger().log("AWSPENDING secret is valid, skipping creation\n");
                    return "Pending secret valid, nothing to do";
                } else {
                    context.getLogger().log("AWSPENDING secret invalid, regenerating...\n");
                }
            } catch (ResourceNotFoundException rnfe) {
                // AWS created metadata but no value yet
                context.getLogger().log("AWSPENDING has no value yet — will generate new secret\n");
            }
        }

        // ✅ Case 2: Either no pending version OR no value for pending
        GetSecretValueResponse current = client.getSecretValue(
                GetSecretValueRequest.builder()
                        .secretId(secretId)
                        .versionStage("AWSCURRENT")
                        .build());
        String currentSecret = current.secretString();

        String newSecret = fetchNewSecretFromExternalSystem(currentSecret, context);
        context.getLogger().log("Generated new pending secret: " + newSecret + "\n");

        client.putSecretValue(PutSecretValueRequest.builder()
                .secretId(secretId)
                .clientRequestToken(token)
                .secretString(newSecret)
                .versionStages("AWSPENDING")
                .build());

        context.getLogger().log("Created new pending secret version.\n");
        return "Created or replaced pending secret version";
    }



//            // 2️⃣ Fetch current secret
//            GetSecretValueResponse current = client.getSecretValue(
//                    GetSecretValueRequest.builder()
//                            .secretId(secretId)
//                            .versionStage("AWSCURRENT")
//                            .build());
//            String currentSecret = current.secretString();
//            context.getLogger().log("Current secret = " + currentSecret + "\n");
//
//            // 3️⃣ Get new secret from external system
//            String newSecret = fetchNewSecretFromExternalSystem(currentSecret, context);
//
//            // 4️⃣ Store as AWSPENDING
//            client.putSecretValue(PutSecretValueRequest.builder()
//                    .secretId(secretId)
//                    .clientRequestToken(token)
//                    .secretString(newSecret)
//                    .versionStages("AWSPENDING")
//                    .build());


    // Example: call external API to generate new secret
    private String fetchNewSecretFromExternalSystem(String currentSecret, Context context) throws Exception {
        //       HttpClient httpClient = HttpClient.newHttpClient();
//        HttpRequest req = HttpRequest.newBuilder()
//                .uri(new URI("https://your-external-service.example.com/get-new-secret"))
//                .header("Content-Type", "application/json")
//                .header("Authorization", "Bearer " + currentSecret)
//                .GET()
//                .build();
//
//        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
//        if (resp.statusCode() != 200) {
//            throw new RuntimeException("External service returned " + resp.statusCode());
//        }
//
//        context.getLogger().log("External service returned new secret\n");
//        return resp.body();
        // Assume JSON like {"username":"..","password":".."}
        String newPassword = UUID.randomUUID().toString().substring(0, 16);

        // Simulate JSON response like an external API would return
        String newSecretJson = String.format("""
        {
            "username": "admin",
            "password": "%s"
        }
        """, newPassword);

        context.getLogger().log("Simulated external API returned new secret: " + newSecretJson + "\n");
        return newSecretJson;
    }

    // Example: validate pending secret
    private boolean testSecretWithExternalSystem(String secret, Context context) {
        try {
            // TODO: replace with actual validation (DB/API call)
            context.getLogger().log("Validating secret: " + secret + "\n");
            return true; // assume valid for demo
        } catch (Exception e) {
            context.getLogger().log("Validation failed: " + e.getMessage() + "\n");
            return false;
        }
    }

    // ===================== STEP 2: SET SECRET =====================
    private String setSecret(String secretId, String token, Context context) {
        try {
            GetSecretValueResponse pending = client.getSecretValue(
                    GetSecretValueRequest.builder()
                            .secretId(secretId)
                            .versionId(token)
                            .versionStage("AWSPENDING")
                            .build());
            context.getLogger().log("Applying pending secret: " + pending.secretString() + "\n");

            // TODO: update DB/API key with pending secret
            return "Set secret applied.";
        } catch (Exception e) {
            context.getLogger().log("Error in setSecret: " + e.getMessage() + "\n");
            throw e;
        }
    }

    // ===================== STEP 3: TEST SECRET =====================
    private String testSecret(String secretId, String token, Context context) {
        try {
            context.getLogger().log("Testing pending secret for " + secretId + "\n");

            GetSecretValueResponse pending = client.getSecretValue(
                    GetSecretValueRequest.builder()
                            .secretId(secretId)
                            .versionId(token)
                            .versionStage("AWSPENDING")
                            .build());

            if (!testSecretWithExternalSystem(pending.secretString(), context)) {
                throw new RuntimeException("Pending secret test failed");
            }

            return "Test succeeded.";
        } catch (Exception e) {
            context.getLogger().log("Test failed: " + e.getMessage() + "\n");
            throw e;
        }
    }

    // ===================== STEP 4: FINISH SECRET =====================
    private String finishSecret(String secretId, String token, Context context) {
        try {
            DescribeSecretResponse describe = client.describeSecret(
                    DescribeSecretRequest.builder().secretId(secretId).build());

            String currentVersion = describe.versionIdsToStages().entrySet().stream()
                    .filter(e -> e.getValue().contains("AWSCURRENT"))
                    .map(Map.Entry::getKey)
                    .findFirst()
                    .orElse(null);

            client.updateSecretVersionStage(UpdateSecretVersionStageRequest.builder()
                    .secretId(secretId)
                    .versionStage("AWSCURRENT")
                    .moveToVersionId(token)
                    .removeFromVersionId(currentVersion)
                    .build());

            context.getLogger().log("Promoted pending version to AWSCURRENT.\n");
            return "Finished rotation.";
        } catch (Exception e) {
            context.getLogger().log("Error in finishSecret: " + e.getMessage() + "\n");
            throw e;
        }
    }
}
