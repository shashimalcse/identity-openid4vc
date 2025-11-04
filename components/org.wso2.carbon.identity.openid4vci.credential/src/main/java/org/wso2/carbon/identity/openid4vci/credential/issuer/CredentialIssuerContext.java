package org.wso2.carbon.identity.openid4vci.credential.issuer;

import org.wso2.carbon.identity.vc.config.management.model.VCCredentialConfiguration;

import java.util.HashMap;
import java.util.Map;

/**
 * Context holder for credential issuance process.
 */
public class CredentialIssuerContext {

    private VCCredentialConfiguration credentialConfiguration;
    private String configurationId;
    private String tenantDomain;
    private Map<String, String> claims;

    public CredentialIssuerContext() {
        this.claims = new HashMap<>();
    }

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

    public Map<String, String> getClaims() {
        return claims;
    }

    public void setClaims(Map<String, String> claims) {
        this.claims = claims;
    }
}
