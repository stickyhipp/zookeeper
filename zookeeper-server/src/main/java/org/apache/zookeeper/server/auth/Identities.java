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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper class for a List of Identity objects.
 */
public class Identities {
    private static final Logger LOG = LoggerFactory.getLogger(Identities.class);

    private List<Identity> ids;
    private String idString;

    // type + name must be unique identity
    public Identities(final String id) {
        this.idString = id;
        this.ids = parseIdString(id);
    }

    public List<Identity> getIds() {
        return this.ids;
    }

    @Override
    public String toString() {
        return idString;
    }

    public String getIdsAsString() {
        if (ids == null || ids.size() < 1) {
            return "";
        }
        final StringBuilder result = new StringBuilder();
        result.append(ids.get(0).toString());
        ids.stream().skip(1).forEach(identity -> {
            result.append(",").append(identity);
        });
        return result.toString();
    }

    /**
     * Parse input string
     * @param id a comma-separated list of identities formatted as type:name
     * @return a list of Identity objects
     */
    private List<Identity> parseIdString(final String id) {
        List<Identity> idsList = new ArrayList<>();
        if (id == null) {
            return idsList;
        }
        String[] parts = id.split(",");
        for (String part : parts) {
            final int index = part.indexOf(':');
            final String type = index >= 0 ? part.substring(0, index) : "";
            final String name = part.substring(index + 1);

            if (type.equals(Identity.Type.USER.name)) {
                idsList.add(new Identity(Identity.Type.USER, name));
            } else if (type.equals(Identity.Type.SERVICE_IDENTITY.name)) {
                idsList.add(new Identity(Identity.Type.SERVICE_IDENTITY, name));
            } else if (type.equals(Identity.Type.HOST.name)) {
                idsList.add(new Identity(Identity.Type.HOST, name));
            } else if (type.equals(Identity.Type.HOST_TIER.name)) {
                idsList.add(new Identity(Identity.Type.HOST_TIER, name));
            } else if (type.equals(Identity.Type.JOB.name)) {
                idsList.add(new Identity(Identity.Type.JOB, name));
            } else {
                LOG.warn("Unknown identity type found when parsing idString: \"{}\"", type);
                // make sure that any unexpectedly-formatted id string still gets traced in some form,
                // instead of just being ignored...
                idsList.add(new Identity(Identity.Type.UNKNOWN_TYPE, part));
            }
        }
        return idsList;
    }
}
