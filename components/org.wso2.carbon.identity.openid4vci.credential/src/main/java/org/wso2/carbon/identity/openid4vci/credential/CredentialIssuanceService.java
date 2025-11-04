package org.wso2.carbon.identity.openid4vci.credential;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.openid4vci.credential.dto.CredentialIssuanceReqDTO;
import org.wso2.carbon.identity.openid4vci.credential.dto.CredentialIssuanceRespDTO;
import org.wso2.carbon.identity.openid4vci.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vci.credential.internal.CredentialIssuanceDataHolder;
import org.wso2.carbon.identity.openid4vci.credential.issuer.CredentialIssuer;
import org.wso2.carbon.identity.openid4vci.credential.issuer.CredentialIssuerContext;
import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;
import org.wso2.carbon.identity.vc.config.management.exception.VCConfigMgtException;
import org.wso2.carbon.identity.vc.config.management.model.VCCredentialConfiguration;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.List;
import java.util.Map;

/**
 * Default implementation for credential issuance processing.
 */
public class CredentialIssuanceService {

    private static final Log log = LogFactory.getLog(CredentialIssuanceService.class);
    private final CredentialIssuer credentialIssuer;

    public CredentialIssuanceService() {
        this.credentialIssuer = new CredentialIssuer();
    }

    public CredentialIssuanceRespDTO issueCredential(CredentialIssuanceReqDTO reqDTO)
            throws CredentialIssuanceException {

        if (reqDTO == null) {
            throw new CredentialIssuanceException("Credential issuance request cannot be null");
        }

        VCCredentialConfigManager configManager =
                CredentialIssuanceDataHolder.getInstance().getVcCredentialConfigManager();
        if (configManager == null) {
            throw new CredentialIssuanceException("VC credential configuration manager is not available");
        }

        SignedJWT signedJWT;
        JWTClaimsSet claimsSet;

        AccessTokenDO accessTokenDO = null;
        try {
            accessTokenDO = CredentialIssuanceDataHolder.getInstance().getTokenProvider()
                    .getVerifiedAccessToken(reqDTO.getToken(), false);
        } catch (IdentityOAuth2Exception e) {
            throw new CredentialIssuanceException("Error verifying access token", e);
        }

        String[] scopes  = accessTokenDO.getScope();
        AuthenticatedUser authenticatedUser = accessTokenDO.getAuthzUser();

        try {
            List<VCCredentialConfiguration> credentialConfigurations = configManager.list(reqDTO.getTenantDomain());
            VCCredentialConfiguration credentialConfiguration = credentialConfigurations.stream()
                    .filter(config -> config.getConfigurationId()
                            .equals(reqDTO.getCredentialConfigurationId())).findFirst().orElseThrow(() ->
                            new CredentialIssuanceException("unknown credential configuration: No matching " +
                                    "credential configuration found for ID: " + reqDTO.getCredentialConfigurationId()));

            // Validate scope - check if the required scope exists in JWT token
            validateScope(scopes, credentialConfiguration.getScope());


            UserRealm realm = IdentityTenantUtil.getRealm(reqDTO.getTenantDomain(),
                    authenticatedUser.toFullQualifiedUsername());

            Map<String, String> claims = realm.getUserStoreManager().getUserClaimValues(MultitenantUtils
                            .getTenantAwareUsername(authenticatedUser.toFullQualifiedUsername()),
                    credentialConfiguration.getClaims().toArray(new String[0]), null);
            claims.put("id", authenticatedUser.getUserId());

            CredentialIssuerContext issuerContext = new CredentialIssuerContext();
            issuerContext.setConfigurationId(credentialConfiguration.getId());
            issuerContext.setCredentialConfiguration(credentialConfiguration);
            issuerContext.setTenantDomain(reqDTO.getTenantDomain());
            issuerContext.setClaims(claims);

            String credential = credentialIssuer.issueCredential(issuerContext);
            CredentialIssuanceRespDTO respDTO = new CredentialIssuanceRespDTO();
            respDTO.setCredential(credential);
            return respDTO;


        } catch (VCConfigMgtException e) {
            throw new CredentialIssuanceException("Error retrieving credential configurations for tenant: "
                    + reqDTO.getTenantDomain(), e);
        } catch (IdentityException e) {
            throw new CredentialIssuanceException("Error retrieving user realm for tenant: "
                    + reqDTO.getTenantDomain(), e);
        } catch (UserStoreException e) {
            throw new CredentialIssuanceException("Error retrieving user claims for user: "
                    + authenticatedUser.toFullQualifiedUsername(), e);
        }
    }

    /**
     * Validates if the required scope from credential configuration exists in the JWT token scope.
     *
     * @param scopes the scopes from token
     * @param requiredScope the scope required by the credential configuration
     * @throws CredentialIssuanceException if the required scope is not present in JWT token
     */
    private void validateScope(String[] scopes, String requiredScope) throws CredentialIssuanceException {

        for (String scope : scopes) {
            if (requiredScope.equals(scope)) {
                if (log.isDebugEnabled()) {
                    log.debug("Required scope: " + requiredScope + " is present in access token scopes");
                }
                return;
            }
        }

        throw new CredentialIssuanceException("Access token does not contain the required scope: "
                + requiredScope);
    }
}
