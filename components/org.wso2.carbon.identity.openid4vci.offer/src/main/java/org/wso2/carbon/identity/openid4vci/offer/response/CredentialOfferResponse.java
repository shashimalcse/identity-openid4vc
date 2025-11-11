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

package org.wso2.carbon.identity.openid4vci.offer.response;

import java.util.Collections;
import java.util.Map;

/**
 * Response wrapper containing credential offer values.
 */
public class CredentialOfferResponse {

    private final Map<String, Object> offer;

    public CredentialOfferResponse(Map<String, Object> offer) {

        this.offer = offer == null ? Collections.emptyMap() : offer;
    }

    public Map<String, Object> getOffer() {

        return Collections.unmodifiableMap(offer);
    }
}

