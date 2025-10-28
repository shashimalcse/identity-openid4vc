package org.wso2.carbon.identity.openid4vci.endpoint.metadata.factories;

import org.wso2.carbon.identity.openid4vci.metadata.response.builder.CredentialIssuerMetadataResponseBuilder;
import org.wso2.carbon.identity.openid4vci.metadata.response.builder.impl.CredentialIssuerMetadataJSONResponseBuilder;

/**
 * Factory providing metadata response builders.
 */
public class CredentialIssuerMetadataResponseBuilderFactory {

    private static final CredentialIssuerMetadataResponseBuilder RESPONSE_BUILDER =
            new CredentialIssuerMetadataJSONResponseBuilder();

    private CredentialIssuerMetadataResponseBuilderFactory() {

    }

    public static CredentialIssuerMetadataResponseBuilder getResponseBuilder() {

        return RESPONSE_BUILDER;
    }
}
