package com.example.rotation;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.PutSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.*;

import java.util.Map;
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
                return createSecret(secretId, token, context);
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

    private String createSecret(String secretId, String token, Context context) {
        try {
            DescribeSecretResponse describe = client.describeSecret(
                    DescribeSecretRequest.builder().secretId(secretId).build());

            // ✅ Check if version already exists
            if (describe.versionIdsToStages().containsKey(token)) {
                context.getLogger().log("Version already exists for token " + token + ", skipping creation.\n");
                return "Secret version already exists, skipping putSecretValue.";
            }

            // Get current secret
            GetSecretValueResponse current = client.getSecretValue(
                    GetSecretValueRequest.builder()
                            .secretId(secretId)
                            .versionStage("AWSCURRENT")
                            .build());

            String currentSecret = current.secretString();
            context.getLogger().log("Current secret = " + currentSecret + "\n");

            // Generate new one
            String newSecretJson = "{\"username\":\"admin\",\"password\":\"" +
                    UUID.randomUUID().toString().substring(0, 16) + "\"}";

            client.putSecretValue(PutSecretValueRequest.builder()
                    .secretId(secretId)
                    .clientRequestToken(token)
                    .secretString(newSecretJson)
                    .versionStages("AWSPENDING")
                    .build());

            return "Created new secret version.";
        } catch (Exception e) {
            context.getLogger().log("Error in createSecret: " + e.getMessage());
            throw e;
        }
    }

    private String setSecret(String secretId, String token, Context context) {
        try {
            GetSecretValueResponse pending = client.getSecretValue(
                    GetSecretValueRequest.builder()
                            .secretId(secretId)
                            .versionStage("AWSPENDING")
                            .versionId(token)
                            .build());

            context.getLogger().log("Applying pending secret: " + pending.secretString() + "\n");

            // (Here you'd update your DB or API key)

            return "Set secret applied.";
        } catch (Exception e) {
            context.getLogger().log("Error in setSecret: " + e.getMessage());
            throw e;
        }
    }

    private String testSecret(String secretId, String token, Context context) {
        try {
            // (Simulate testing connectivity)
            context.getLogger().log("Testing pending secret for " + secretId + "\n");
            return "Test succeeded.";
        } catch (Exception e) {
            context.getLogger().log("Test failed: " + e.getMessage());
            throw e;
        }
    }

    private String finishSecret(String secretId, String token, Context context) {
        try {
            DescribeSecretResponse describe = client.describeSecret(
                    DescribeSecretRequest.builder().secretId(secretId).build());

            // Find the current version
            String currentVersion = describe.versionIdsToStages().entrySet().stream()
                    .filter(e -> e.getValue().contains("AWSCURRENT"))
                    .map(Map.Entry::getKey)
                    .findFirst()
                    .orElse(null);

            // Promote pending to current
            client.updateSecretVersionStage(UpdateSecretVersionStageRequest.builder()
                    .secretId(secretId)
                    .versionStage("AWSCURRENT")
                    .moveToVersionId(token)
                    .removeFromVersionId(currentVersion)
                    .build());

            context.getLogger().log("Promoted pending version to AWSCURRENT.\n");
            return "Finished rotation.";
        } catch (Exception e) {
            context.getLogger().log("Error in finishSecret: " + e.getMessage());
            throw e;
        }
    }
}


