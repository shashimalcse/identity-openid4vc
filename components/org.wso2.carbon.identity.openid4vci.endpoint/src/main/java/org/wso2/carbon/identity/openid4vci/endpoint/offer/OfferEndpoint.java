/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.openid4vci.endpoint.offer;

import com.google.gson.Gson;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.openid4vci.endpoint.offer.factories.CredentialOfferServiceFactory;
import org.wso2.carbon.identity.openid4vci.offer.CredentialOfferProcessor;
import org.wso2.carbon.identity.openid4vci.offer.exception.CredentialOfferException;
import org.wso2.carbon.identity.openid4vci.offer.response.CredentialOfferResponse;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * REST implementation of OID4VCI credential offer endpoint.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class OfferEndpoint {

    private static final Log log = LogFactory.getLog(OfferEndpoint.class);
    private static final Gson GSON = new Gson();
    public static final String TENANT_NAME_FROM_CONTEXT = "TenantNameFromContext";

    @GET
    @Path("/credential-offer/{offer_id}")
    public Response getCredentialOffer(
            @PathParam("offer_id") String offerId) {

        String tenantDomain = resolveTenantDomain();

        if (StringUtils.isEmpty(offerId)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("{\"error\":\"invalid_request\"," +
                            "\"error_description\":\"offer_id is required\"}")
                    .build();
        }

        try {
            CredentialOfferProcessor processor = CredentialOfferServiceFactory.getOfferProcessor();
            CredentialOfferResponse offerResponse = processor.generateOffer(offerId, tenantDomain);
            String responsePayload = GSON.toJson(offerResponse.getOffer());
            return Response.ok(responsePayload, MediaType.APPLICATION_JSON).build();
        } catch (CredentialOfferException e) {
            log.error(String.format("Error while generating credential offer for tenant: %s", tenantDomain), e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{\"error\":\"server_error\",\"error_description\":\"" + e.getMessage() + "\"}")
                    .build();
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

