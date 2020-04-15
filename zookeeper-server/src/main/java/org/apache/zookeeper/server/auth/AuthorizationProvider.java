/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.zookeeper.server.auth;

/**
 * Authorization interface to check permission based on
 * identity, resource and action.
 */
public interface AuthorizationProvider {

    class AuthorizationResult {
        public final boolean authorized;
        public final boolean shadow;
        public final Identity authorizedId;

        AuthorizationResult(boolean authorized, boolean shadow, Identity authorizedId) {
            this.authorized = authorized;
            this.shadow = shadow;
            this.authorizedId = authorizedId;
        }

        public boolean isAccepted() {
            return authorized || shadow;
        }
    }

    /**
     * Check if connection is authorized for the specified identity.
     *
     * @param identities client identity.
     * @return  true if connection is permitted.
     */
    AuthorizationResult checkConnectPermission(final Identities identities);

    boolean isAdmin(final Identities identities);

}
