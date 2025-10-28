package org.wso2.carbon.identity.openid4vci.metadata;

import org.wso2.carbon.identity.openid4vci.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vci.metadata.response.CredentialIssuerMetadataResponse;

/**
 * Processor interface for constructing OpenID4VCI credential issuer metadata.
 */
public interface CredentialIssuerMetadataProcessor {

    /**
     * Build the metadata response for a given tenant.
     *
     * @param tenantDomain Tenant domain resolving the credential issuer.
     * @return Metadata response payload.
     * @throws CredentialIssuerMetadataException On metadata retrieval failures.
     */
    CredentialIssuerMetadataResponse getMetadataResponse(String tenantDomain)
            throws CredentialIssuerMetadataException;
}
