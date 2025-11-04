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
import org.wso2.carbon.identity.openid4vci.credential.response.CredentialIssuanceResponse;
import org.wso2.carbon.identity.openid4vci.endpoint.credential.error.CredentialErrorResponse;
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
            // Validate Authorization header (Section 8.3.1.1 - Authorization Errors)
            String authHeader = request.getHeader("Authorization");
            if (StringUtils.isEmpty(authHeader) || !authHeader.startsWith("Bearer ")) {
                String errorResponse = CredentialErrorResponse.builder()
                        .error(CredentialErrorResponse.INVALID_TOKEN)
                        .errorDescription("Missing or invalid Authorization header")
                        .build()
                        .toJson();
                return Response.status(Response.Status.UNAUTHORIZED)
                        .header("Cache-Control", "no-store")
                        .entity(errorResponse)
                        .build();
            }



            // Parse the JSON payload to extract credential_configuration_id
            JsonObject jsonObject;
            try {
                jsonObject = JsonParser.parseString(payload).getAsJsonObject();
            } catch (JsonSyntaxException e) {
                log.error("Invalid JSON payload", e);
                String errorResponse = CredentialErrorResponse.builder()
                        .error(CredentialErrorResponse.INVALID_CREDENTIAL_REQUEST)
                        .errorDescription("Invalid JSON format")
                        .build()
                        .toJson();
                return Response.status(Response.Status.BAD_REQUEST).entity(errorResponse).build();
            }

            // Validate required field: credential_configuration_id
            if (!jsonObject.has("credential_configuration_id")) {
                String errorResponse = CredentialErrorResponse.builder()
                        .error(CredentialErrorResponse.INVALID_CREDENTIAL_REQUEST)
                        .errorDescription("Missing required field: credential_configuration_id")
                        .build()
                        .toJson();
                return Response.status(Response.Status.BAD_REQUEST).entity(errorResponse).build();
            }

            String credentialConfigurationId = jsonObject.get("credential_configuration_id").getAsString();

            String token = authHeader.substring(7); // Remove "Bearer " prefix

            // Build CredentialIssuanceReqDTO directly
            CredentialIssuanceReqDTO credentialIssuanceReqDTO = new CredentialIssuanceReqDTO();
            credentialIssuanceReqDTO.setTenantDomain(resolveTenantDomain());
            credentialIssuanceReqDTO.setCredentialConfigurationId(credentialConfigurationId);
            credentialIssuanceReqDTO.setToken(token);

            // Issue credential
            CredentialIssuanceService credentialIssuanceService = CredentialIssuanceServiceFactory
                    .getCredentialIssuanceService();
            CredentialIssuanceRespDTO credentialIssuanceRespDTO = credentialIssuanceService
                    .issueCredential(credentialIssuanceReqDTO);
            return buildResponse(credentialIssuanceRespDTO);

        } catch (CredentialIssuanceException e) {
            String tenantDomain = resolveTenantDomain();
            if (log.isDebugEnabled()) {
                log.debug(String.format("Credential issuance failed for tenant: %s", tenantDomain), e);
            }

            // Map exception to appropriate OpenID4VCI error code
            String errorCode = mapExceptionToErrorCode(e);
            String errorResponse = CredentialErrorResponse.builder()
                    .error(errorCode)
                    .errorDescription(e.getMessage())
                    .build()
                    .toJson();

            // Return 403 Forbidden for insufficient_scope, 400 Bad Request for others
            Response.Status status = CredentialErrorResponse.INSUFFICIENT_SCOPE.equals(errorCode)
                    ? Response.Status.FORBIDDEN
                    : Response.Status.BAD_REQUEST;

            return Response.status(status)
                    .header("Cache-Control", "no-store")
                    .entity(errorResponse)
                    .build();
        } catch (IllegalStateException e) {
            log.error("Credential issuance processor service is unavailable", e);
            String errorResponse = CredentialErrorResponse.builder()
                    .error(CredentialErrorResponse.CREDENTIAL_REQUEST_DENIED)
                    .errorDescription("Credential issuance service is unavailable")
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .header("Cache-Control", "no-store")
                    .entity(errorResponse)
                    .build();
        } catch (Exception e) {
            log.error("Error building credential response", e);
            String errorResponse = CredentialErrorResponse.builder()
                    .error(CredentialErrorResponse.CREDENTIAL_REQUEST_DENIED)
                    .errorDescription("Error processing credential request")
                    .build()
                    .toJson();
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .header("Cache-Control", "no-store")
                    .entity(errorResponse)
                    .build();
        }
    }

    /**
     * Maps CredentialIssuanceException to appropriate OpenID4VCI error code.
     *
     * @param exception the credential issuance exception
     * @return the appropriate error code
     */
    private String mapExceptionToErrorCode(CredentialIssuanceException exception) {
        String message = exception.getMessage();
        if (message == null) {
            return CredentialErrorResponse.CREDENTIAL_REQUEST_DENIED;
        }

        // Map based on exception message patterns
        if (message.contains("insufficient_scope")) {
            return CredentialErrorResponse.INSUFFICIENT_SCOPE;
        } else if (message.contains("unknown") && message.contains("configuration")) {
            return CredentialErrorResponse.UNKNOWN_CREDENTIAL_CONFIGURATION;
        } else if (message.contains("unknown") && message.contains("identifier")) {
            return CredentialErrorResponse.UNKNOWN_CREDENTIAL_IDENTIFIER;
        } else if (message.contains("proof")) {
            return CredentialErrorResponse.INVALID_PROOF;
        } else if (message.contains("nonce")) {
            return CredentialErrorResponse.INVALID_NONCE;
        } else if (message.contains("encryption")) {
            return CredentialErrorResponse.INVALID_ENCRYPTION_PARAMETERS;
        } else if (message.contains("denied")) {
            return CredentialErrorResponse.CREDENTIAL_REQUEST_DENIED;
        } else {
            return CredentialErrorResponse.INVALID_CREDENTIAL_REQUEST;
        }
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
