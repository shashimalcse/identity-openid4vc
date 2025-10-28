package org.wso2.carbon.identity.openid4vci.metadata.exception;

/**
 * Exception thrown when building credential issuer metadata fails.
 */
public class CredentialIssuerMetadataException extends Exception {

    public CredentialIssuerMetadataException(String message) {

        super(message);
    }

    public CredentialIssuerMetadataException(String message, Throwable cause) {

        super(message, cause);
    }
}
