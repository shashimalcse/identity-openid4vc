package org.wso2.carbon.identity.openid4vci.common.util;

import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;

/**
 * Utility class for OID4VCI component.
 */
public class Util {

    public static ServiceURL buildServiceUrl(String tenantDomain, String... pathSegments) throws URLBuilderException {

        ServiceURLBuilder builder = ServiceURLBuilder.create().addPath(pathSegments);
        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            builder.setTenant(tenantDomain);
        }
        return builder.build();
    }
}
