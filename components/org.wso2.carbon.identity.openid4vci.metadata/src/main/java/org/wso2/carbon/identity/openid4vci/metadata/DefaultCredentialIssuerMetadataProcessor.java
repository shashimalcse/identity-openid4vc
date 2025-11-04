package org.wso2.carbon.identity.openid4vci.metadata;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.openid4vci.common.constant.Constants;
import org.wso2.carbon.identity.openid4vci.common.util.Util;
import org.wso2.carbon.identity.openid4vci.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vci.metadata.internal.CredentialIssuerMetadataDataHolder;
import org.wso2.carbon.identity.openid4vci.metadata.response.CredentialIssuerMetadataResponse;
import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;
import org.wso2.carbon.identity.vc.config.management.exception.VCConfigMgtException;
import org.wso2.carbon.identity.vc.config.management.model.VCCredentialConfiguration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


/**
 * Default implementation for credential issuer metadata processing.
 */
public class DefaultCredentialIssuerMetadataProcessor implements CredentialIssuerMetadataProcessor {

    private static final Log log = LogFactory.getLog(DefaultCredentialIssuerMetadataProcessor.class);
    private static final DefaultCredentialIssuerMetadataProcessor defaultCredentialIssuerMetadataProcessor =
            new DefaultCredentialIssuerMetadataProcessor();

    private DefaultCredentialIssuerMetadataProcessor() {

        if (log.isDebugEnabled()) {
            log.debug("Initializing DefaultCredentialIssuerMetadataProcessor for " +
                    "CredentialIssuerMetadataProcessor.");
        }
    }

    public static DefaultCredentialIssuerMetadataProcessor getInstance() {

        return defaultCredentialIssuerMetadataProcessor;
    }

    @Override
    public CredentialIssuerMetadataResponse getMetadataResponse(String tenantDomain)
            throws CredentialIssuerMetadataException {

        String effectiveTenant = resolveTenant(tenantDomain);
        try {
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("credential_issuer", buildCredentialIssuerUrl(effectiveTenant));
            metadata.put("credential_endpoint", buildCredentialEndpointUrl(effectiveTenant));
            metadata.put("authorization_servers",
                    Collections.singletonList(buildAuthorizationServerUrl(effectiveTenant)));
            Map<String, Object> credentialConfigurations = getCredentialConfigurations(effectiveTenant);
            metadata.put("credential_configurations_supported", credentialConfigurations);

            return new CredentialIssuerMetadataResponse(metadata);
        } catch (URLBuilderException e) {
            throw new CredentialIssuerMetadataException("Error while constructing credential issuer metadata URLs", e);
        }
    }

    private String resolveTenant(String tenantDomain) {

        if (tenantDomain == null || tenantDomain.trim().isEmpty()) {
            return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }

    private String buildCredentialIssuerUrl(String tenantDomain) throws URLBuilderException {

        return Util.buildServiceUrl(tenantDomain, Constants.CONTEXT_OPENID4VCI).getAbsolutePublicURL();
    }

    private String buildCredentialEndpointUrl(String tenantDomain) throws URLBuilderException {

        return Util.buildServiceUrl(tenantDomain, Constants.CONTEXT_OPENID4VCI, Constants.SEGMENT_CREDENTIAL)
                .getAbsolutePublicURL();
    }

    private String buildAuthorizationServerUrl(String tenantDomain) throws URLBuilderException {

        return Util.buildServiceUrl(tenantDomain, Constants.SEGMENT_OAUTH2, Constants.SEGMENT_TOKEN)
                .getAbsolutePublicURL();
    }

    protected Map<String, Object> getCredentialConfigurations(String tenantDomain)
            throws CredentialIssuerMetadataException {

        VCCredentialConfigManager configManager = CredentialIssuerMetadataDataHolder.getInstance()
                .getVCCredentialConfigManager();
        try {
            List<VCCredentialConfiguration> configurations = configManager.list(tenantDomain);

            Map<String, Object> configurationsMap = new LinkedHashMap<>();
            if (configurations == null || configurations.isEmpty()) {
                return configurationsMap;
            }

            for (VCCredentialConfiguration cfg : configurations) {
                Map<String, Object> cfgMap = new LinkedHashMap<>();

                // Basic fields
                cfgMap.put("id", cfg.getConfigurationId());
                cfgMap.put("format", cfg.getFormat());
                cfgMap.put("scope", cfg.getScope());

                // Signing algorithms
                List<String> algValues = new ArrayList<>();
                if (cfg.getSigningAlgorithm() != null) {
                    algValues.add(cfg.getSigningAlgorithm());
                }
                cfgMap.put("credential_signing_alg_values_supported", algValues);

                // VCT
                cfgMap.put("vct", cfg.getType());

                // credential_definition: type and @context
                Map<String, Object> credentialDefinition = new LinkedHashMap<>();
                List<String> types = new ArrayList<>();
                types.add(cfg.getType());
                credentialDefinition.put("type", types);
                List<String> contexts = new ArrayList<>();
                contexts.add(cfg.getType());
                credentialDefinition.put("@context", contexts);
                cfgMap.put("credential_definition", credentialDefinition);

                // credential_metadata: display and claims in the expected structure
                Map<String, Object> credentialMetadata = new LinkedHashMap<>();
                VCCredentialConfiguration.Metadata meta = cfg.getMetadata();
                credentialMetadata.put("display", buildDisplay(meta));
                credentialMetadata.put("claims", buildClaimsList(cfg.getClaims()));
                cfgMap.put("credential_metadata", credentialMetadata);
                configurationsMap.put(cfg.getConfigurationId(), cfgMap);
            }

            return configurationsMap;
        } catch (VCConfigMgtException e) {
            throw new CredentialIssuerMetadataException("Error while retrieving VC credential configurations " +
                    "for tenant: " + tenantDomain, e);
        }
    }

    private Object buildDisplay(VCCredentialConfiguration.Metadata meta) {

        if (meta == null || meta.getDisplay() == null) {
            return Collections.emptyList();
        }
        try {
            return new Gson().fromJson(meta.getDisplay(), Object.class);
        } catch (JsonSyntaxException e) {
            if (log.isDebugEnabled()) {
                log.debug("Invalid JSON in credential metadata display; returning empty list. JSON: "
                        + meta.getDisplay(), e);
            }
            return Collections.emptyList();
        }
    }

    private List<Map<String, Object>> buildClaimsList(List<String> claims) {

        if (claims == null) {
            return Collections.emptyList();
        }
        return claims.stream().map(claim -> {
                    Map<String, Object> claimMap = new LinkedHashMap<>();
                    claimMap.put("path", Collections.singletonList(claim));
                    return claimMap;
                }).collect(Collectors.toList());
    }
}
