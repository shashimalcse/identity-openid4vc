package org.wso2.carbon.identity.openid4vci.credential.response;

import com.google.gson.Gson;
import org.wso2.carbon.identity.openid4vci.credential.exception.CredentialIssuanceException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Represents the response generated after issuing an OpenID4VCI credential.
 */
public class CredentialIssuanceResponse {

    private static final Gson GSON = new Gson();
    private final Map<String, Object> payload;

    private CredentialIssuanceResponse(Map<String, Object> payload) {
        this.payload = payload;
    }

    public String toJson() {
        return GSON.toJson(payload);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for constructing CredentialIssuanceResponse instances.
     */
    public static class Builder {
        private final Map<String, Object> payload = new HashMap<>();

        public Builder credential(String credential) {
            if (credential == null) {
                throw new IllegalArgumentException("Credential cannot be null");
            }
            // Create the structure: { "credentials": [ { "credential": "<credential-string>" } ] }
            List<Map<String, Object>> credentialsList = new ArrayList<>();
            Map<String, Object> credentialObject = new HashMap<>();
            credentialObject.put("credential", credential);
            credentialsList.add(credentialObject);
            payload.put("credentials", credentialsList);
            return this;
        }

        public Builder cNonceExpiresIn(Long expiresIn) {
            payload.put("c_nonce_expires_in", expiresIn);
            return this;
        }

        public CredentialIssuanceResponse build() throws CredentialIssuanceException {
            if (!payload.containsKey("credentials")) {
                throw new CredentialIssuanceException("Credential is required");
            }
            return new CredentialIssuanceResponse(payload);
        }
    }
}
