package org.wso2.carbon.identity.openid4vci.endpoint.credential;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vci.credential.CredentialIssuanceService;
import org.wso2.carbon.identity.openid4vci.credential.dto.CredentialIssuanceReqDTO;
import org.wso2.carbon.identity.openid4vci.credential.dto.CredentialIssuanceRespDTO;
import org.wso2.carbon.identity.openid4vci.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vci.credential.model.CredentialIssuanceRequest;
import org.wso2.carbon.identity.openid4vci.credential.response.CredentialIssuanceResponse;
import org.wso2.carbon.identity.openid4vci.endpoint.credential.factories.CredentialIssuanceServiceFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Rest implementation of OID4VCI credential endpoint.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class CredentialEndpoint {

    private static final Log log = LogFactory.getLog(CredentialEndpoint.class);
    public static final String TENANT_NAME_FROM_CONTEXT = "TenantNameFromContext";

    @POST
    @Path("/credential")
    @Consumes("application/json")
    @Produces("application/json")
    public Response requestCredential(@Context HttpServletRequest request, @Context HttpServletResponse response,
                                      String payload) {

        try {
            // Parse the JSON payload to extract fields
            JsonObject jsonObject = JsonParser.parseString(payload).getAsJsonObject();

            // Extract credential_configuration_id from the JSON payload
            if (!jsonObject.has("credential_configuration_id")) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("{\"error\":\"Missing required field: credential_configuration_id\"}").build();
            }

            String credentialConfigurationId = jsonObject.get("credential_configuration_id").getAsString();

            // Create CredentialIssuanceRequest object to carry the information
            CredentialIssuanceRequest credentialRequest = new CredentialIssuanceRequest();
            credentialRequest.setCredentialConfigurationId(credentialConfigurationId);

            CredentialIssuanceService credentialIssuanceService = CredentialIssuanceServiceFactory
                    .getCredentialIssuanceService();
            CredentialIssuanceReqDTO credentialIssuanceReqDTO = buildCredentialIssuanceReqDTO(credentialRequest);
            CredentialIssuanceRespDTO credentialIssuanceRespDTO = credentialIssuanceService
                    .issueCredential(credentialIssuanceReqDTO);
            return buildResponse(credentialIssuanceRespDTO);
        } catch (JsonSyntaxException e) {
            log.error("Invalid JSON payload", e);
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"Invalid JSON format\"}").build();
        } catch (CredentialIssuanceException e) {
            String tenantDomain = resolveTenantDomain();
            if (log.isDebugEnabled()) {
                log.debug(String.format("Credential issuance failed for tenant: %s", tenantDomain), e);
            }
            return Response.status(Response.Status.BAD_REQUEST).entity(e.getMessage()).build();
        } catch (IllegalStateException e) {
            log.error("Credential issuance processor service is unavailable", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Credential issuance service is unavailable").build();
        } catch (Exception e) {
            log.error("Error building credential response", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Error building credential response").build();
        }
    }

    private CredentialIssuanceReqDTO buildCredentialIssuanceReqDTO(CredentialIssuanceRequest credentialRequest) {

        CredentialIssuanceReqDTO reqDTO = new CredentialIssuanceReqDTO();
        String tenantDomain = resolveTenantDomain();
        reqDTO.setTenantDomain(tenantDomain);
        reqDTO.setCredentialConfigurationId(credentialRequest.getCredentialConfigurationId());
        return reqDTO;
    }

    private Response buildResponse(CredentialIssuanceRespDTO credentialIssuanceRespDTO)
            throws CredentialIssuanceException {

        String payload = CredentialIssuanceResponse.builder()
                .credential(credentialIssuanceRespDTO.getCredential())
                .build()
                .toJson();
        return Response.ok(payload, MediaType.APPLICATION_JSON).build();
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
