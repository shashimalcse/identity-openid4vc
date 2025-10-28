package org.wso2.carbon.identity.openid4vci.metadata;

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
    private static final String SEGMENT_AUTHORIZE = "authorize";

    private static final Log log = LogFactory.getLog(DefaultCredentialIssuerMetadataProcessor.class);
    private static DefaultCredentialIssuerMetadataProcessor defaultCredentialIssuerMetadataProcessor =
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
                    Collections.singletonList(buildAuthorizeEndpointUrl(effectiveTenant)));
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

    private String buildAuthorizeEndpointUrl(String tenantDomain) throws URLBuilderException {

        return buildServiceUrl(tenantDomain, SEGMENT_OAUTH2, SEGMENT_AUTHORIZE).getAbsolutePublicURL();
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

                // credential_metadata: display and claims
                Map<String, Object> credentialMetadata = new LinkedHashMap<>();
                Object meta = cfg.getCredentialMetadata();
                if (meta != null) {
                    try {
                        // Use provided display list directly
                        Object displayList = meta.getClass().getMethod("getDisplay").invoke(meta);
                        credentialMetadata.put("display", displayList != null ? displayList : Collections.emptyList());
                    } catch (ReflectiveOperationException ignore) {
                        // If method not found, default to empty list
                        credentialMetadata.put("display", Collections.emptyList());
                    }
                } else {
                    credentialMetadata.put("display", Collections.emptyList());
                }

                Object claims = cfg.getClaimMappings();
                credentialMetadata.put("claims", claims != null ? claims : Collections.emptyList());

                cfgMap.put("credential_metadata", credentialMetadata);

                configurationsMap.put(cfg.getConfigurationId(), cfgMap);
            }

            return configurationsMap;
        } catch (VCConfigMgtException e) {
            throw new CredentialIssuerMetadataException("Error while retrieving VC credential configurations " +
                    "for tenant: " + tenantDomain, e);
        }
    }
}
