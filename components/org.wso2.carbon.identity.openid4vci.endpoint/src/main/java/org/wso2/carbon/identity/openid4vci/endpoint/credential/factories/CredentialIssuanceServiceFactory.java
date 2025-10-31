package org.wso2.carbon.identity.openid4vci.endpoint.credential.factories;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.openid4vci.credential.CredentialIssuanceService;

/**
 * Factory for retrieving the credential issuance processor instance.
 */
public class CredentialIssuanceServiceFactory {

    private static final CredentialIssuanceService SERVICE;

    static {
        CredentialIssuanceService credentialIssuanceService = (CredentialIssuanceService) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(CredentialIssuanceService.class, null);

        if (credentialIssuanceService == null) {
            throw new IllegalStateException("CredentialIssuanceService is not available from OSGI context.");
        }
        SERVICE = credentialIssuanceService;
    }

    public static CredentialIssuanceService getCredentialIssuanceService() {

        return SERVICE;
    }
}
