package org.wso2.carbon.identity.openid4vci.metadata;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.openid4vci.metadata.exception.CredentialIssuerMetadataException;
import org.wso2.carbon.identity.openid4vci.metadata.internal.CredentialIssuerMetadataDataHolder;
import org.wso2.carbon.identity.openid4vci.metadata.response.CredentialIssuerMetadataResponse;
import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;
import org.wso2.carbon.identity.vc.config.management.exception.VCConfigMgtException;
import org.wso2.carbon.identity.vc.config.management.model.ClaimMapping;
import org.wso2.carbon.identity.vc.config.management.model.VCCredentialConfiguration;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Default implementation for credential issuer metadata processing.
 */
public class DefaultCredentialIssuerMetadataProcessor implements CredentialIssuerMetadataProcessor {

    private static final String CONTEXT_OPENID4VCI = "oid4vci";
    private static final String SEGMENT_CREDENTIAL = "credential";
    private static final String SEGMENT_OAUTH2 = "oauth2";
    private static final String SEGMENT_TOKEN = "token";

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

        return buildServiceUrl(tenantDomain, CONTEXT_OPENID4VCI).getAbsolutePublicURL();
    }

    private String buildCredentialEndpointUrl(String tenantDomain) throws URLBuilderException {

        return buildServiceUrl(tenantDomain, CONTEXT_OPENID4VCI, SEGMENT_CREDENTIAL).getAbsolutePublicURL();
    }

    private String buildAuthorizationServerUrl(String tenantDomain) throws URLBuilderException {

        return buildServiceUrl(tenantDomain, SEGMENT_OAUTH2, SEGMENT_TOKEN).getAbsolutePublicURL();
    }

    private ServiceURL buildServiceUrl(String tenantDomain, String... pathSegments) throws URLBuilderException {

        ServiceURLBuilder builder = ServiceURLBuilder.create().addPath(pathSegments);
        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
            builder.setTenant(tenantDomain);
        }
        return builder.build();
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
                if (cfg.getCredentialSigningAlgValuesSupported() != null) {
                    algValues.add(cfg.getCredentialSigningAlgValuesSupported());
                }
                cfgMap.put("credential_signing_alg_values_supported", algValues);

                // VCT URL
                cfgMap.put("vct", cfg.getCredentialType());

                // credential_definition: type and @context
                Map<String, Object> credentialDefinition = new LinkedHashMap<>();
                List<String> types = new ArrayList<>();
                types.add(cfg.getCredentialType());
                credentialDefinition.put("type", types);
                List<String> contexts = new ArrayList<>();
                contexts.add(cfg.getCredentialType());
                credentialDefinition.put("@context", contexts);
                cfgMap.put("credential_definition", credentialDefinition);

                // credential_metadata: display and claims in the expected structure
                Map<String, Object> credentialMetadata = new LinkedHashMap<>();
                Object meta = cfg.getCredentialMetadata();
                credentialMetadata.put("display", buildDisplay(meta));
                credentialMetadata.put("claims", buildClaimsList(cfg.getClaimMappings()));
                cfgMap.put("credential_metadata", credentialMetadata);
                configurationsMap.put(cfg.getConfigurationId(), cfgMap);
            }

            return configurationsMap;
        } catch (VCConfigMgtException e) {
            throw new CredentialIssuerMetadataException("Error while retrieving VC credential configurations " +
                    "for tenant: " + tenantDomain, e);
        }
    }

    private Object buildDisplay(Object meta) {

        if (meta == null) {
            return Collections.emptyList();
        }
        try {
            Object display = meta.getClass().getMethod("getDisplay").invoke(meta);
            if (display == null) {
                return Collections.emptyList();
            }
            // If the display is persisted as a JSON string, parse and return as-is
            if (display instanceof String) {
                String json = (String) display;
                try {
                    return new Gson().fromJson(json, Object.class);
                } catch (JsonSyntaxException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid JSON in credential metadata display; returning empty list. JSON: "
                                + json, e);
                    }
                    return Collections.emptyList();
                }
            }
            // If already a List/Map structure, return directly without reshaping
            if (display instanceof List || display instanceof Map) {
                return display;
            }
            // Fallback
            return Collections.emptyList();
        } catch (ReflectiveOperationException e) {
            if (log.isDebugEnabled()) {
                log.debug("Unable to access display from credential metadata; returning empty list.", e);
            }
            return Collections.emptyList();
        }
    }

    private List<Map<String, Object>> buildClaimsList(List<ClaimMapping> claimMappings) {

        if (claimMappings == null) {
            return Collections.emptyList();
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (ClaimMapping claimMapping: claimMappings) {
            Map<String, Object> cmMap = new LinkedHashMap<>();

            List<String> pathList = new ArrayList<>();
            pathList.add(claimMapping.getClaimURI());
            cmMap.put("path", pathList);

            List<Map<String, Object>> display = new ArrayList<>();
            if (claimMapping.getDisplay() != null) {
                Map<String, Object> diMap = new LinkedHashMap<>();
                diMap.put("name", claimMapping.getDisplay());
                display.add(diMap);
                cmMap.put("display", display);
            }

            if (!cmMap.isEmpty()) {
                result.add(cmMap);
            }
        }
        return result;
    }
}
