package org.wso2.carbon.identity.openid4vci.endpoint.metadata;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vci.endpoint.metadata.factories.CredentialIssuerMetadataResponseBuilderFactory;
import org.wso2.carbon.identity.openid4vci.endpoint.metadata.factories.CredentialIssuerMetadataServiceFactory;
import org.wso2.carbon.identity.openid4vci.metadata.CredentialIssuerMetadataProcessor;
import org.wso2.carbon.identity.openid4vci.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vci.metadata.response.CredentialIssuerMetadataResponse;
import org.wso2.carbon.identity.openid4vci.metadata.response.builder.CredentialIssuerMetadataResponseBuilder;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Rest implementation of OID4VCI metadata endpoint.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class MetadataEndpoint {

    private static final Log log = LogFactory.getLog(MetadataEndpoint.class);
    public static final String TENANT_NAME_FROM_CONTEXT = "TenantNameFromContext";

    @GET
    @Path("/.well-known/openid-credential-issuer")
    public Response getIssuerMetadata() {

        String tenantDomain = resolveTenantDomain();
        try {
            CredentialIssuerMetadataProcessor processor =
                    CredentialIssuerMetadataServiceFactory.getMetadataProcessor();
            CredentialIssuerMetadataResponseBuilder responseBuilder =
                    CredentialIssuerMetadataResponseBuilderFactory.getResponseBuilder();
            CredentialIssuerMetadataResponse metadataResponse =
                    processor.getMetadataResponse(tenantDomain);
            String responsePayload = responseBuilder.build(metadataResponse);
            return Response.ok(responsePayload, MediaType.APPLICATION_JSON).build();
        } catch (CredentialIssuerMetadataException e) {
            log.error(String.format("Error while resolving OpenID4VCI metadata for tenant: %s", tenantDomain), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.getMessage()).build();
        }
    }

    private String resolveTenantDomain() {

        String tenantDomain = null;
        Object tenantObj = IdentityUtil.threadLocalProperties.get().get(TENANT_NAME_FROM_CONTEXT);
        if (tenantObj != null) {
            tenantDomain = (String) tenantObj;
        }
        if (StringUtils.isEmpty(tenantDomain)) {
            tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }
}
