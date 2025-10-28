package org.wso2.carbon.identity.openid4vci.metadata.response.builder;

import org.wso2.carbon.identity.openid4vci.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vci.metadata.response.CredentialIssuerMetadataResponse;

/**
 * Builder responsible for serializing credential issuer metadata responses.
 */
public interface CredentialIssuerMetadataResponseBuilder {

    /**
     * Build a serialized metadata payload.
     *
     * @param metadataResponse Metadata response wrapper.
     * @return Serialized payload, typically JSON.
     * @throws CredentialIssuerMetadataException On serialization errors.
     */
    String build(CredentialIssuerMetadataResponse metadataResponse) throws CredentialIssuerMetadataException;
}
