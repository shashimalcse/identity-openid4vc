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

package org.wso2.carbon.identity.openid4vci.endpoint.offer.factories;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.openid4vci.offer.CredentialOfferProcessor;
import org.wso2.carbon.identity.openid4vci.offer.DefaultCredentialOfferProcessor;

/**
 * Factory class for obtaining CredentialOfferProcessor instances.
 */
public class CredentialOfferServiceFactory {

    private static final DefaultCredentialOfferProcessor OFFER_PROCESSOR;

    static {
        DefaultCredentialOfferProcessor defaultCredentialOfferProcessor
                = (DefaultCredentialOfferProcessor) PrivilegedCarbonContext
                .getThreadLocalCarbonContext().getOSGiService(CredentialOfferProcessor.class, null);

        if (defaultCredentialOfferProcessor == null) {
            throw new IllegalStateException("DefaultCredentialOfferProcessor is not available from " +
                    "OSGI context.");
        }
        OFFER_PROCESSOR = defaultCredentialOfferProcessor;
    }

    public static CredentialOfferProcessor getOfferProcessor() {

        return OFFER_PROCESSOR;
    }
}

