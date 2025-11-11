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

package org.wso2.carbon.identity.openid4vci.offer.internal;

import org.wso2.carbon.identity.vc.config.management.VCCredentialConfigManager;
import org.wso2.carbon.identity.vc.config.management.VCOfferManager;

/**
 * Data holder for OID4VCI Credential Offer.
 */
public class CredentialOfferDataHolder {

    private static final CredentialOfferDataHolder instance = new CredentialOfferDataHolder();

    private VCOfferManager vcOfferManager;
    private VCCredentialConfigManager vcCredentialConfigManager;

    public static CredentialOfferDataHolder getInstance() {
        return instance;
    }

    public void setVCOfferManager(VCOfferManager vcOfferManager) {
        this.vcOfferManager = vcOfferManager;
    }

    public VCOfferManager getVCOfferManager() {
        return vcOfferManager;
    }

    public VCCredentialConfigManager getVcCredentialConfigManager() {

        return vcCredentialConfigManager;
    }

    public void setVcCredentialConfigManager(VCCredentialConfigManager vcCredentialConfigManager) {

        this.vcCredentialConfigManager = vcCredentialConfigManager;
    }
}

