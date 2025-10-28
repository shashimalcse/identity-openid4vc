package org.wso2.carbon.identity.openid4vci.metadata.response.builder.impl;

import com.google.gson.Gson;
import org.wso2.carbon.identity.openid4vci.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vci.metadata.response.CredentialIssuerMetadataResponse;
import org.wso2.carbon.identity.openid4vci.metadata.response.builder.CredentialIssuerMetadataResponseBuilder;

import java.util.Map;

/**
 * Build JSON responses for credential issuer metadata.
 */
public class CredentialIssuerMetadataJSONResponseBuilder implements CredentialIssuerMetadataResponseBuilder {

    private static final Gson GSON = new Gson();

    @Override
    public String build(CredentialIssuerMetadataResponse metadataResponse) throws CredentialIssuerMetadataException {

        if (metadataResponse == null) {
            throw new CredentialIssuerMetadataException("Metadata response is null");
        }
        Map<String, Object> metadata = metadataResponse.getMetadata();
        return GSON.toJson(metadata);
    }
}
