package org.wso2.carbon.identity.openid4vci.metadata.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.openid4vci.metadata.CredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vci.metadata.DefaultCredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;

/**
 * Service component for OID4VCI Credential Issuer Metadata.
 */
@Component(
        name = "identity.openid4vci.metadata.component",
        immediate = true
)
public class CredentialIssuerMetadataServiceComponent {
    private static final Log log = LogFactory.getLog(CredentialIssuerMetadataServiceComponent.class);
    private static BundleContext bundleContext = null;

    public static BundleContext getBundleContext() {
        return bundleContext;
    }

    protected void activate(ComponentContext context) {
        try {
            bundleContext = context.getBundleContext();
            // exposing server configuration as a service
            bundleContext.registerService(CredentialIssuerMetadataProcessor.class.getName(),
                    DefaultCredentialIssuerMetadataProcessor.getInstance(), null);
            if (log.isDebugEnabled()) {
                log.debug("OID4VCI Credential Issuer Metadata bundle is activated");
            }
        } catch (Throwable e) {
            log.error("Error while activating CredentialIssuerMetadataServiceComponent", e);
        }
    }

    @Reference(
            name = "vc.config.mgt.service.component",
            service = VCCredentialConfigManager.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetVCCredentialConfigManager"
    )
    protected void setVCCredentialConfigManager(VCCredentialConfigManager vcCredentialConfigManager) {

        CredentialIssuerMetadataDataHolder.getInstance().setVCCredentialConfigManager(vcCredentialConfigManager);
    }

    protected void unsetVCCredentialConfigManager(VCCredentialConfigManager vcCredentialConfigManager) {

        CredentialIssuerMetadataDataHolder.getInstance().setVCCredentialConfigManager(null);
    }

}
