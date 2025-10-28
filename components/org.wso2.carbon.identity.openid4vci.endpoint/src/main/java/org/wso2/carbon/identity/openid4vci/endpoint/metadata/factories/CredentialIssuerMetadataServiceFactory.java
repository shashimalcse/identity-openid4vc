package org.wso2.carbon.identity.openid4vci.endpoint.metadata.factories;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.openid4vci.metadata.CredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vci.metadata.DefaultCredentialIssuerMetadataProcessor;

/**
 * Factory for retrieving the credential issuer metadata processor instance.
 */
public class CredentialIssuerMetadataServiceFactory {

    private static final DefaultCredentialIssuerMetadataProcessor METADATA_PROCESSOR;

    static {
        DefaultCredentialIssuerMetadataProcessor defaultCredentialIssuerMetadataProcessor
                = (DefaultCredentialIssuerMetadataProcessor) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(CredentialIssuerMetadataProcessor.class, null);

        if (defaultCredentialIssuerMetadataProcessor == null) {
            throw new IllegalStateException("DefaultCredentialIssuerMetadataProcessor is not available from " +
                    "OSGI context.");
        }
        METADATA_PROCESSOR = defaultCredentialIssuerMetadataProcessor;
    }

    public static CredentialIssuerMetadataProcessor getMetadataProcessor() {

        return METADATA_PROCESSOR;
    }
}
