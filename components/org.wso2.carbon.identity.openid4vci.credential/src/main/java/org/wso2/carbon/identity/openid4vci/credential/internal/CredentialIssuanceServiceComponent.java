package org.wso2.carbon.identity.openid4vci.credential.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.openid4vci.credential.CredentialIssuanceService;
import org.wso2.carbon.identity.openid4vci.credential.issuer.handlers.format.CredentialFormatHandler;
import org.wso2.carbon.identity.openid4vci.credential.issuer.handlers.format.impl.JwtVcJsonFormatHandler;
import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;

/**
 * Service component for credential issuance operations.
 */
@Component(
        name = "identity.openid4vci.credential.component",
        immediate = true
)
public class CredentialIssuanceServiceComponent {

    private static final Log log = LogFactory.getLog(CredentialIssuanceServiceComponent.class);


    protected void activate(ComponentContext context) {

        try {
            BundleContext bundleContext = context.getBundleContext();
            bundleContext.registerService(CredentialIssuanceService.class, new CredentialIssuanceService(), null);
            bundleContext.registerService(CredentialFormatHandler.class, new JwtVcJsonFormatHandler(), null);
            if (log.isDebugEnabled()) {
                log.debug("OID4VCI credential issuance component activated");
            }
        } catch (Throwable throwable) {
            log.error("Error while activating CredentialIssuanceServiceComponent", throwable);
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

        CredentialIssuanceDataHolder.getInstance().setVcCredentialConfigManager(vcCredentialConfigManager);
    }

    protected void unsetVCCredentialConfigManager(VCCredentialConfigManager vcCredentialConfigManager) {

        CredentialIssuanceDataHolder.getInstance().setVcCredentialConfigManager(null);
    }

    @Reference(
            name = "openid4vci.issuer.credential.handler.format",
            service = CredentialFormatHandler.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "removeScopeValidationHandler"
    )
    protected void addCredentialFormatHandler(CredentialFormatHandler credentialFormatHandler) {

        if (log.isDebugEnabled()) {
            log.debug("Adding the CredentialFormatHandler Service : " + credentialFormatHandler.getFormat());
        }
        CredentialIssuanceDataHolder.getInstance().addCredentialFormatHandler(credentialFormatHandler);
    }

    protected void removeScopeValidationHandler(CredentialFormatHandler credentialFormatHandler) {

        if (log.isDebugEnabled()) {
            log.debug("Removing the CredentialFormatHandler Service : " + credentialFormatHandler.getFormat());
        }
        CredentialIssuanceDataHolder.getInstance().removeCredentialFormatHandler(credentialFormatHandler);
    }
}
