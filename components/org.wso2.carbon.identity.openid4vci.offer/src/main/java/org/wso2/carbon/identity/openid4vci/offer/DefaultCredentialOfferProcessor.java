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

package org.wso2.carbon.identity.openid4vci.offer;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.openid4vci.common.constant.Constants;
import org.wso2.carbon.identity.openid4vci.common.util.Util;
import org.wso2.carbon.identity.openid4vci.offer.exception.CredentialOfferException;
import org.wso2.carbon.identity.openid4vci.offer.internal.CredentialOfferDataHolder;
import org.wso2.carbon.identity.openid4vci.offer.response.CredentialOfferResponse;
import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;
import org.wso2.carbon.identity.vc.config.management.VCOfferManager;
import org.wso2.carbon.identity.vc.config.management.exception.VCConfigMgtException;
import org.wso2.carbon.identity.vc.config.management.model.VCOffer;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Default implementation for credential offer processing.
 */
public class DefaultCredentialOfferProcessor implements CredentialOfferProcessor {

    private static final Log log = LogFactory.getLog(DefaultCredentialOfferProcessor.class);
    private static final DefaultCredentialOfferProcessor defaultCredentialOfferProcessor =
            new DefaultCredentialOfferProcessor();

    private DefaultCredentialOfferProcessor() {

        if (log.isDebugEnabled()) {
            log.debug("Initializing DefaultCredentialOfferProcessor for CredentialOfferProcessor.");
        }
    }

    public static DefaultCredentialOfferProcessor getInstance() {

        return defaultCredentialOfferProcessor;
    }

    @Override
    public CredentialOfferResponse generateOffer(String offerId, String tenantDomain)
            throws CredentialOfferException {

        try {
            Map<String, Object> offer = new LinkedHashMap<>();

            // Set credential issuer URL
            offer.put("credential_issuer", buildCredentialIssuerUrl(tenantDomain));

            List<String> credentialConfigurationIdentifiers = getCredentialConfigurationIdentifiers(offerId,
                    tenantDomain);

            // Set credential configuration IDs
            offer.put("credential_configuration_ids", credentialConfigurationIdentifiers);

            // Build grants structure
            Map<String, Object> grants = new LinkedHashMap<>();
            Map<String, Object> authCodeGrant = new LinkedHashMap<>();

            // Set authorization server URL
            authCodeGrant.put("authorization_server", buildAuthorizationServerUrl(tenantDomain));

            grants.put("authorization_code", authCodeGrant);
            offer.put("grants", grants);

            return new CredentialOfferResponse(offer);
        } catch (URLBuilderException e) {
            throw new CredentialOfferException("Error while constructing credential offer URLs", e);
        } catch (VCConfigMgtException e) {
            throw new CredentialOfferException("Error while retrieving VC offer", e);
        }
    }

    private static List<String> getCredentialConfigurationIdentifiers(String offerId, String tenantDomain)
            throws VCConfigMgtException {

        VCOfferManager vcOfferManager = CredentialOfferDataHolder.getInstance().getVCOfferManager();
        VCOffer vcOffer = vcOfferManager.get(offerId, tenantDomain);

        VCCredentialConfigManager vcCredentialConfigManager = CredentialOfferDataHolder.getInstance()
                .getVcCredentialConfigManager();

        // Get identifiers from VCCredentialConfig for each credential configuration ID
        List<String> credentialConfigurationIdentifiers = new ArrayList<>();
        for (String credentialConfigId : vcOffer.getCredentialConfigurationIds()) {
            String identifier = vcCredentialConfigManager.get(credentialConfigId, tenantDomain).getIdentifier();
            credentialConfigurationIdentifiers.add(identifier);
        }
        return credentialConfigurationIdentifiers;
    }

    private String buildCredentialIssuerUrl(String tenantDomain) throws URLBuilderException {

        return Util.buildServiceUrl(tenantDomain, Constants.CONTEXT_OPENID4VCI).getAbsolutePublicURL();
    }

    private String buildAuthorizationServerUrl(String tenantDomain) throws URLBuilderException {

        return Util.buildServiceUrl(tenantDomain, Constants.SEGMENT_OAUTH2, Constants.SEGMENT_TOKEN)
                .getAbsolutePublicURL();
    }
}

