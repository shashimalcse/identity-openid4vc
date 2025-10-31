package org.wso2.carbon.identity.openid4vci.credential.dto;

/**
 * DTO for credential issuance response.
 */
public class CredentialIssuanceRespDTO {

    private String credential;

    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }
}
