package org.wso2.carbon.identity.openid4vci.credential.util;

import org.wso2.carbon.identity.core.IdentityKeyStoreResolver;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverConstants;
import org.wso2.carbon.identity.core.util.IdentityKeyStoreResolverException;
import org.wso2.carbon.identity.openid4vci.credential.exception.CredentialIssuanceException;

import java.security.Key;

/**
 * Utility class for credential issuance related operations.
 */
public class CredentialIssuanceUtil {

    /**
     * Method to obtain the tenant's private key for OAuth2 protocol.
     * This could be the primary keystore private key, tenant keystore private key,
     * or a custom keystore private key.
     *
     * @param tenantDomain Tenant Domain as a String.
     * @return Private key for OAuth2 protocol in the tenant domain.
     * @throws CredentialIssuanceException When failed to obtain the private key for the requested tenant.
     */
    public static Key getPrivateKey(String tenantDomain) throws CredentialIssuanceException {
        try {
            return IdentityKeyStoreResolver.getInstance().getPrivateKey(
                    tenantDomain, IdentityKeyStoreResolverConstants.InboundProtocol.OAUTH);
        } catch (IdentityKeyStoreResolverException e) {
            throw new CredentialIssuanceException("Error while obtaining private key", e);
        }
    }
}
