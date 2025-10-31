package org.wso2.carbon.identity.openid4vci.credential;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vci.credential.dto.CredentialIssuanceReqDTO;
import org.wso2.carbon.identity.openid4vci.credential.dto.CredentialIssuanceRespDTO;
import org.wso2.carbon.identity.openid4vci.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vci.credential.internal.CredentialIssuanceDataHolder;
import org.wso2.carbon.identity.openid4vci.credential.issuer.CredentialIssuer;
import org.wso2.carbon.identity.openid4vci.credential.issuer.CredentialIssuerContext;
import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;
import org.wso2.carbon.identity.vc.config.management.exception.VCConfigMgtException;
import org.wso2.carbon.identity.vc.config.management.model.VCCredentialConfiguration;

import java.util.List;

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


        try {
            List<VCCredentialConfiguration> credentialConfigurations = configManager.list(reqDTO.getTenantDomain());
            VCCredentialConfiguration credentialConfiguration = credentialConfigurations.stream()
                    .filter(config -> config.getConfigurationId()
                            .equals(reqDTO.getCredentialConfigurationId())).findFirst().orElseThrow(() ->
                            new CredentialIssuanceException("No matching credential configuration found for ID: "
                            + reqDTO.getCredentialConfigurationId()));
            CredentialIssuerContext issuerContext = new CredentialIssuerContext();
            issuerContext.setConfigurationId(credentialConfiguration.getId());
            issuerContext.setCredentialConfiguration(credentialConfiguration);
            issuerContext.setTenantDomain(reqDTO.getTenantDomain());

            String credential = credentialIssuer.issueCredential(issuerContext);
            CredentialIssuanceRespDTO respDTO = new CredentialIssuanceRespDTO();
            respDTO.setCredential(credential);
            return respDTO;


        } catch (VCConfigMgtException e) {
            throw new CredentialIssuanceException("Error retrieving credential configurations for tenant: "
                    + reqDTO.getTenantDomain(), e);
        }
    }
}
