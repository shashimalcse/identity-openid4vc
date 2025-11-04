/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vci.endpoint.credential.error;

import com.google.gson.Gson;

import java.util.HashMap;
import java.util.Map;

/**
 * Represents an error response for credential issuance requests as per OpenID4VCI specification.
 */
public class CredentialErrorResponse {

    private static final Gson GSON = new Gson();

    // Error codes as per OpenID4VCI spec Section 8.3.1.2
    public static final String INVALID_CREDENTIAL_REQUEST = "invalid_credential_request";
    public static final String UNKNOWN_CREDENTIAL_CONFIGURATION = "unknown_credential_configuration";
    public static final String UNKNOWN_CREDENTIAL_IDENTIFIER = "unknown_credential_identifier";
    public static final String INVALID_PROOF = "invalid_proof";
    public static final String INVALID_NONCE = "invalid_nonce";
    public static final String INVALID_ENCRYPTION_PARAMETERS = "invalid_encryption_parameters";
    public static final String CREDENTIAL_REQUEST_DENIED = "credential_request_denied";

    // RFC6750 error codes for authorization errors
    public static final String INVALID_TOKEN = "invalid_token";
    public static final String INSUFFICIENT_SCOPE = "insufficient_scope";

    private final String error;
    private final String errorDescription;

    private CredentialErrorResponse(String error, String errorDescription) {
        this.error = error;
        this.errorDescription = errorDescription;
    }

    public String toJson() {
        Map<String, String> errorMap = new HashMap<>();
        errorMap.put("error", error);
        if (errorDescription != null && !errorDescription.isEmpty()) {
            errorMap.put("error_description", errorDescription);
        }
        return GSON.toJson(errorMap);
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder class for constructing CredentialErrorResponse instances.
     */
    public static class Builder {
        private String error;
        private String errorDescription;

        public Builder error(String error) {
            this.error = error;
            return this;
        }

        public Builder errorDescription(String errorDescription) {
            this.errorDescription = errorDescription;
            return this;
        }

        public CredentialErrorResponse build() {
            if (error == null || error.isEmpty()) {
                throw new IllegalArgumentException("Error code is required");
            }
            return new CredentialErrorResponse(error, errorDescription);
        }
    }
}

