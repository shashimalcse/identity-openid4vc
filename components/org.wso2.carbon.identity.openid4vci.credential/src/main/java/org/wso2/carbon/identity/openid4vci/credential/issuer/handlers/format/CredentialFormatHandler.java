package org.wso2.carbon.identity.openid4vci.credential.issuer.handlers.format;

import org.wso2.carbon.identity.openid4vci.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vci.credential.issuer.CredentialIssuerContext;

/**
 * Interface for handling different credential formats.
 */
public interface CredentialFormatHandler {

    /**
     * Get the format identifier supported by this handler.
     *
     * @return format identifier (e.g., "jwt_vc_json", "ldp_vc", "vc+sd-jwt")
     */
    String getFormat();

    /**
     * Issue a credential in the specific format.
     *
     * @param credentialIssuerContext the credential issuer context containing necessary data
     * @return the formatted credential as a string
     * @throws CredentialIssuanceException if credential issuance fails
     */
    String issueCredential(CredentialIssuerContext credentialIssuerContext)
            throws CredentialIssuanceException;
}

