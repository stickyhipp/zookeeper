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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class EnsembleACLConfig implements ACLConfig {
    private int permission;
    private List<Identity> identities;

    public EnsembleACLConfig() {}

    // for testing
    public EnsembleACLConfig(final int permission, final List<Identity> identities) {
        this.permission = permission;
        this.identities = new ArrayList<>(identities);
    }

    public List<Identity> getIdentities() {
        return Collections.unmodifiableList(identities);
    }

    public int getPermission() {
        return permission;
    }
}
