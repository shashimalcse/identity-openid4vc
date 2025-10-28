package org.wso2.carbon.identity.openid4vci.metadata.internal;

import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;

/**
 * Data holder for OID4VCI Credential Issuer Metadata.
 */
public class CredentialIssuerMetadataDataHolder {

    private static CredentialIssuerMetadataDataHolder instance = new CredentialIssuerMetadataDataHolder();
    public static CredentialIssuerMetadataDataHolder getInstance() {
        return instance;
    }
    private VCCredentialConfigManager vcCredentialConfigManager;


    public void setVCCredentialConfigManager(VCCredentialConfigManager vcCredentialConfigManager) {
        this.vcCredentialConfigManager = vcCredentialConfigManager;
    }

    public VCCredentialConfigManager getVCCredentialConfigManager() {
        return vcCredentialConfigManager;
    }
}
