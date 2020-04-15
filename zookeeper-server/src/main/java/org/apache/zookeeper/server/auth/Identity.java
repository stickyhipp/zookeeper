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

/**
 * Security identity with name and type.
 * Type has five kinds: USER, SERVICE_IDENTITY, HOST, HOST_TIER, and JOB.
 *
 * The combination of name and type should constitute a unique identity.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Identity {
    // type + name must be unique identity
    protected Type type;
    protected String name;

    public enum Type {
        USER("user"),
        SERVICE_IDENTITY("svc"),
        HOST("host"),
        HOST_TIER("host_tier"),
        JOB("job"),

        UNKNOWN_TYPE("");

        String name;

        Type(String name) {
            this.name = name;
        }
    }

    public Identity() {}

    public Identity(final Type type, final String name) {
        this.type = type;
        this.name = name;
    }

    public Type getType() {
        return this.type;
    }

    public String getName() {
        return this.name;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (!(obj instanceof Identity)) {
            return false;
        }

        Identity identity = (Identity) obj;
        return this.type == identity.type && this.name != null && this.name.equals(identity.getName());
    }

    @Override
    public int hashCode() {
        final int p = 31;
        int hash = 1;
        hash = p * hash + (type == null ? 0 : type.hashCode());
        hash = p * hash + (name == null ? 0 : name.hashCode());
        return hash;
    }

    @Override
    public String toString() {
        return (type == null ? "" : type.name) + ":" + name;
    }
}
