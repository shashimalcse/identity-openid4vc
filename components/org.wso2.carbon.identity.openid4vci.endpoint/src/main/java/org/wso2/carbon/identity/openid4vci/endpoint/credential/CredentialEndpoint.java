package org.wso2.carbon.identity.openid4vci.endpoint.credential;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Rest implementation of OID4VCI credential endpoint.
 */
@Path("/")
@Produces(MediaType.APPLICATION_JSON)
public class CredentialEndpoint {

    @POST
    @Path("/credential")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response requestCredential() {

        return Response.status(Response.Status.NOT_IMPLEMENTED).build();
    }
}
