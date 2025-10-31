package org.wso2.carbon.identity.openid4vci.credential.issuer;

import org.wso2.carbon.identity.vc.config.management.model.VCCredentialConfiguration;

/**
 * Context holder for credential issuance process.
 */
public class CredentialIssuerContext {

    private VCCredentialConfiguration credentialConfiguration;
    private String configurationId;
    private String tenantDomain;

    public VCCredentialConfiguration getCredentialConfiguration() {
        return credentialConfiguration;
    }

    public void setCredentialConfiguration(VCCredentialConfiguration credentialConfiguration) {
        this.credentialConfiguration = credentialConfiguration;
    }

    public String getConfigurationId() {
        return configurationId;
    }

    public void setConfigurationId(String configurationId) {
        this.configurationId = configurationId;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public void setTenantDomain(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }
}
