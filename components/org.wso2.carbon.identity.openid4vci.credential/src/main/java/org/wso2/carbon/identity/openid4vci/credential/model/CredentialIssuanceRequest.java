package org.wso2.carbon.identity.openid4vci.credential.model;

/**
 * Represents an OpenID4VCI credential issuance request payload.
 */
public class CredentialIssuanceRequest {

    private String credentialConfigurationId;
    private String scope;

    public String getCredentialConfigurationId() {
        return credentialConfigurationId;
    }

    public void setCredentialConfigurationId(String credentialConfigurationId) {
        this.credentialConfigurationId = credentialConfigurationId;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }
}
