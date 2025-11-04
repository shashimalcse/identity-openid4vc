package org.wso2.carbon.identity.openid4vci.credential.dto;

/**
 * DTO for credential issuance request.
 */
public class CredentialIssuanceReqDTO {

    private String tenantDomain;
    private String credentialConfigurationId;
    private String token;

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    public String getCredentialConfigurationId() {
        return credentialConfigurationId;
    }

    public void setCredentialConfigurationId(String credentialConfigurationId) {
        this.credentialConfigurationId = credentialConfigurationId;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
