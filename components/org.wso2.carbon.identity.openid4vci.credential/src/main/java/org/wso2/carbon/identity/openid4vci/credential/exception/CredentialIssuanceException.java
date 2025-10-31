package org.wso2.carbon.identity.openid4vci.credential.exception;

/**
 * Exception type for credential issuance related failures.
 */
public class CredentialIssuanceException extends Exception {

    public CredentialIssuanceException(String message) {

        super(message);
    }

    public CredentialIssuanceException(String message, Throwable cause) {

        super(message, cause);
    }
}
