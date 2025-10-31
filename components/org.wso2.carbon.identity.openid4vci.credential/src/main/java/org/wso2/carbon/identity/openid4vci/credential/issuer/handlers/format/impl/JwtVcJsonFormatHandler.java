package org.wso2.carbon.identity.openid4vci.credential.issuer.handlers.format.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openid4vci.common.util.Util;
import org.wso2.carbon.identity.openid4vci.credential.exception.CredentialIssuanceException;
import org.wso2.carbon.identity.openid4vci.credential.issuer.CredentialIssuerContext;
import org.wso2.carbon.identity.openid4vci.credential.issuer.handlers.format.CredentialFormatHandler;
import org.wso2.carbon.identity.openid4vci.credential.util.CredentialIssuanceUtil;

import java.security.Key;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;

import static org.wso2.carbon.identity.openid4vci.common.constant.Constants.CONTEXT_OPENID4VCI;

/**
 * Handler for JWT VC JSON format credentials.
 */
public class JwtVcJsonFormatHandler implements CredentialFormatHandler {

    private static final Log log = LogFactory.getLog(JwtVcJsonFormatHandler.class);
    private static final String FORMAT = "jwt_vc_json";

    @Override
    public String getFormat() {
        return FORMAT;
    }

    @Override
    public String issueCredential(CredentialIssuerContext credentialIssuerContext) throws CredentialIssuanceException {

        if (log.isDebugEnabled()) {
            log.debug("Issuing JWT VC JSON credential for configuration: " +
                    credentialIssuerContext.getConfigurationId());
        }

        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(credentialIssuerContext);
        String signedJWT = signJWT(jwtClaimsSet, credentialIssuerContext);
        return signedJWT;
    }

    private JWTClaimsSet createJWTClaimSet(CredentialIssuerContext credentialIssuerContext)
            throws CredentialIssuanceException {

        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
        String issuer;
        try {
            issuer = buildCredentialIssuerUrl(credentialIssuerContext.getTenantDomain());
        } catch (URLBuilderException e) {
            throw new CredentialIssuanceException("Error building credential issuer URL", e);
        }
        jwtClaimsSetBuilder.issuer(issuer);
        return jwtClaimsSetBuilder.build();
    }

    private String buildCredentialIssuerUrl(String tenantDomain) throws URLBuilderException {

        return Util.buildServiceUrl(tenantDomain, CONTEXT_OPENID4VCI).getAbsolutePublicURL();
    }

    private String signJWT(JWTClaimsSet jwtClaimsSet, CredentialIssuerContext credentialIssuerContext)
            throws CredentialIssuanceException {

        String signatureAlgorithm = credentialIssuerContext.getCredentialConfiguration()
                .getCredentialSigningAlgValuesSupported();
        if (JWSAlgorithm.RS256.getName().equals(signatureAlgorithm)) {
            return signJWTWithRSA(jwtClaimsSet, credentialIssuerContext);
        } else {
            throw new CredentialIssuanceException("Invalid signature algorithm provided. " + signatureAlgorithm);
        }
    }

    private String signJWTWithRSA(JWTClaimsSet jwtClaimsSet, CredentialIssuerContext credentialIssuerContext)
            throws CredentialIssuanceException {

        try {
            String tenantDomain = credentialIssuerContext.getTenantDomain();
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);

            Key privateKey = CredentialIssuanceUtil.getPrivateKey(tenantDomain);
            JWSSigner signer = OAuth2Util.createJWSSigner((RSAPrivateKey) privateKey);
            JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
            Certificate certificate = null;
            try {
                certificate = OAuth2Util.getCertificate(tenantDomain, tenantId);
            } catch (IdentityOAuth2Exception e) {
                throw new CredentialIssuanceException("Error obtaining the certificate for tenant: " + tenantDomain, e);
            }
            String certThumbPrint = null;
            try {
                certThumbPrint = OAuth2Util.getThumbPrintWithPrevAlgorithm(certificate, false);
            } catch (IdentityOAuth2Exception e) {
                throw new CredentialIssuanceException("Error obtaining the certificate thumbprint for tenant: "
                        + tenantDomain, e);
            }
            try {
                headerBuilder.keyID(OAuth2Util.getKID(OAuth2Util.getCertificate(tenantDomain, tenantId),
                        (JWSAlgorithm) JWSAlgorithm.RS256, tenantDomain));
            } catch (IdentityOAuth2Exception e) {
                throw new CredentialIssuanceException("Error obtaining the KID for tenant: " + tenantDomain, e);
            }
            headerBuilder.x509CertThumbprint(new Base64URL(certThumbPrint));
            SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), jwtClaimsSet);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new CredentialIssuanceException("Error occurred while signing JWT", e);
        }
    }
}

