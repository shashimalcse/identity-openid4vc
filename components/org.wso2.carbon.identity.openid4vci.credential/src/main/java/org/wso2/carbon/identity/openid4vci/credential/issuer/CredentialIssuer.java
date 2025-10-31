package org.wso2.carbon.identity.openid4vci.credential.issuer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openid4vci.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vci.credential.internal.CredentialIssuanceDataHolder;
import org.wso2.carbon.identity.openid4vci.credential.issuer.handlers.format.CredentialFormatHandler;

import java.util.List;

/**
 * Credential issuer that delegates to format-specific handlers.
 */
public class CredentialIssuer {

    private static final Log log = LogFactory.getLog(CredentialIssuer.class);

    /**
     * Issue a credential based on the format.
     *
     * @param credentialIssuerContext the credential issuer context containing necessary data
     * @return the issued credential
     * @throws CredentialIssuanceException if issuance fails or format is not supported
     */
    public String issueCredential(CredentialIssuerContext credentialIssuerContext)
            throws CredentialIssuanceException {

        if (credentialIssuerContext.getCredentialConfiguration().getFormat() == null) {
            throw new CredentialIssuanceException("Credential format cannot be null");
        }

        String format = credentialIssuerContext.getCredentialConfiguration().getFormat();
        List<CredentialFormatHandler> formatHandlers = CredentialIssuanceDataHolder.getInstance()
                .getCredentialFormatHandlers();
        CredentialFormatHandler handler = formatHandlers.stream()
                .filter(h -> format.equals(h.getFormat()))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unsupported credential format: " + format));
        if (log.isDebugEnabled()) {
            log.debug("Issuing credential with format: " + format +
                     " for configuration: " + credentialIssuerContext.getConfigurationId());
        }

        return handler.issueCredential(credentialIssuerContext);
    }
}

