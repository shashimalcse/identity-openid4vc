package org.wso2.carbon.identity.openid4vci.credential.internal;

import org.wso2.carbon.identity.oauth.tokenprocessor.DefaultTokenProvider;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenProvider;
import org.wso2.carbon.identity.openid4vci.credential.issuer.handlers.format.CredentialFormatHandler;
import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;

import java.util.ArrayList;
import java.util.List;

/**
 * Data holder for OID4VCI credential issuance component.
 */
public class CredentialIssuanceDataHolder {

    private static final CredentialIssuanceDataHolder instance = new CredentialIssuanceDataHolder();
    private VCCredentialConfigManager vcCredentialConfigManager;
    private final List<CredentialFormatHandler> credentialFormatHandlers = new ArrayList<>();
    private TokenProvider tokenProvider;

    private CredentialIssuanceDataHolder() {

    }

    public static CredentialIssuanceDataHolder getInstance() {

        return instance;
    }

    public VCCredentialConfigManager getVcCredentialConfigManager() {

        return vcCredentialConfigManager;
    }

    public void setVcCredentialConfigManager(VCCredentialConfigManager vcCredentialConfigManager) {

        this.vcCredentialConfigManager = vcCredentialConfigManager;
    }

    public List<CredentialFormatHandler> getCredentialFormatHandlers() {

        return credentialFormatHandlers;
    }

    public void addCredentialFormatHandler(CredentialFormatHandler handler) {

        this.credentialFormatHandlers.add(handler);
    }

    public void removeCredentialFormatHandler(CredentialFormatHandler handler) {

        this.credentialFormatHandlers.remove(handler);
    }

    public TokenProvider getTokenProvider() {

        if (tokenProvider == null) {
            tokenProvider = new DefaultTokenProvider();
        }
        return tokenProvider;
    }

    public void setTokenProvider(TokenProvider tokenProvider) {

        this.tokenProvider = tokenProvider;
    }
}
