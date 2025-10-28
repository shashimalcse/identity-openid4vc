package org.wso2.carbon.identity.openid4vci.metadata.response;

import java.util.Collections;
import java.util.Map;

/**
 * Response wrapper containing credential issuer metadata values.
 */
public class CredentialIssuerMetadataResponse {

    private final Map<String, Object> metadata;

    public CredentialIssuerMetadataResponse(Map<String, Object> metadata) {

        this.metadata = metadata == null ? Collections.emptyMap() : metadata;
    }

    public Map<String, Object> getMetadata() {

        return Collections.unmodifiableMap(metadata);
    }
}
