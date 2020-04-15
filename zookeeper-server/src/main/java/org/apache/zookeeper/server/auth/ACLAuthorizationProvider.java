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
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.jmx.MBeanRegistry;
import org.apache.zookeeper.jmx.ZKMBeanInfo;
import org.apache.zookeeper.server.DataNode;
import org.apache.zookeeper.server.ServerMetrics;
import org.apache.zookeeper.server.ZKDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.CRC32;

/**
 * AuthorizationProvider using acls to check permissions.
 * ACLs are stored inside znodes under /zookeeper.
 */
public class ACLAuthorizationProvider implements AuthorizationProvider {

    public static final String ZOOKEEPER_ACL_PREFIX = "zookeeper.acl.";
    public static final String REJECT_NULL_IDENTITY = ZOOKEEPER_ACL_PREFIX + "rejectNullIdentity";
    public static final String REJECT_WITHOUT_ACL_DEFINITION = ZOOKEEPER_ACL_PREFIX + "rejectWithoutAclDefinition";
    public static final String FORCE_SHADOW_MODE = ZOOKEEPER_ACL_PREFIX + "forceShadowMode";

    /**
     * default to false to allow connection with null identity to go through.
     * this is compatible with status quo without authorization.
     * but should be set to true for new instances.
     */
    public static boolean rejectNullIdentity = Boolean.getBoolean(REJECT_NULL_IDENTITY);

    /**
     * default to false to allow access when no ACL definition exists or ACL is malformed.
     * Set this property to true to deny access unless permissions are granted in valid ACL.
     */
    public static boolean rejectWithoutAclDefinition = Boolean.getBoolean(REJECT_WITHOUT_ACL_DEFINITION);

    /**
     * default to false to respect the "shadow" setting in ACLConfigs.
     * Set this property to true to force enabling shadow mode and
     * allow everyone to connect in case of an emergency.
     */
    public static boolean forceShadowMode = Boolean.getBoolean(FORCE_SHADOW_MODE);

    private static final Logger LOG = LoggerFactory.getLogger(ACLAuthorizationProvider.class);
    private static final long defaultCheckInterval = 60 * 1000;
    protected static final String aclZookeeper = "/zookeeper/auth/acls";

    private final Map<Identity, Integer> permissions = new ConcurrentHashMap<>(10);
    private final AtomicBoolean shadow = new AtomicBoolean(true);
    private final ZKDatabase zkDb;
    private long aclCRC = -1;

    private final ObjectMapper mapper = new ObjectMapper();
    private final ACLConfigMonitor configMonitor;
    private ACLAuthorizationConfigBean jmxACLAuthorizationConfigBean = null;

    public ACLAuthorizationProvider(final ZKDatabase zkDb) {
        this(zkDb, defaultCheckInterval);
    }

    public ACLAuthorizationProvider(final ZKDatabase zkDb, final long interval) {
        mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS, true);
        this.zkDb = zkDb;
        this.configMonitor = initConfig(interval);

        try {
            jmxACLAuthorizationConfigBean = new ACLAuthorizationConfigBean();
            MBeanRegistry.getInstance().register(jmxACLAuthorizationConfigBean, null);
        } catch (Exception e) {
            LOG.warn("Failed to register acl authorization config bean with JMX", e);
            jmxACLAuthorizationConfigBean = null;
        }

        LOG.info(REJECT_NULL_IDENTITY + " = " + rejectNullIdentity);
        LOG.info(REJECT_WITHOUT_ACL_DEFINITION + " = " + rejectWithoutAclDefinition);
        LOG.info(FORCE_SHADOW_MODE + " = " + forceShadowMode);
    }

    private ACLConfigMonitor initConfig(final long interval) {
        updateAclsFromDataTree();

        ACLConfigMonitor configMonitor = new ACLConfigMonitor(interval);
        configMonitor.start();

        return configMonitor;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ACLConfigs {
        private List<ACLConfig> acl = Collections.emptyList();
        private boolean shadow = true;

        public ACLConfigs() {
        }

        public List<ACLConfig> getAcl() {
            return acl;
        }

        public boolean isShadow() {
            return shadow;
        }
    }

    public class ACLConfigMonitor implements Runnable {
        private final long interval;
        protected Thread thread;
        private volatile boolean running = false;

        public ACLConfigMonitor(final long interval) {
            this.interval = interval;
        }

        @Override
        public void run() {
            while (running) {
                updateAclsFromDataTree();

                if (!running) {
                    break;
                }

                try {
                    Thread.sleep(interval);
                } catch (final InterruptedException ignored) {
                }
            }
        }

        public synchronized void start() {
            if (running) {
                return;
            }

            running = true;
            thread = new Thread(this);
            thread.setDaemon(true);
            thread.start();
        }

    }

    @Override
    public AuthorizationResult checkConnectPermission(final Identities identities) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("checkConnectPerms identities: \"{}\",\nidentities parsed:\"{}\"",
                    identities != null ? identities.toString() : "null",
                    identities != null ? identities.getIdsAsString() : "null");
        }
        boolean authorized;
        Identity authorizedId = null;
        final boolean shadowEnabled = forceShadowMode || shadow.get();

        if (identities == null || identities.getIds().isEmpty()) {
            // authorize null identity unless rejectNullIdentity==true
            authorized = !rejectNullIdentity;
        } else if (permissions.isEmpty()) {
            // no ACL defined. authorize unless rejectWithoutAclDefinition==true
            authorized = !rejectWithoutAclDefinition;
        } else {
            authorized = false;
            for (Identity id : identities.getIds()) {
                if (permissions.containsKey(id)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("permissions contains {}", id);
                    }
                    authorized = true;
                    authorizedId = id;
                    break;
                }
            }
        }

        if (shadowEnabled) {
            if (authorized) {
                ServerMetrics.getMetrics().CONNECTION_AUTHORIZED_SHADOW.add(1);
            } else {
                ServerMetrics.getMetrics().CONNECTION_UNAUTHORIZED_SHADOW.add(1);
            }
        } else {
            if (authorized) {
                ServerMetrics.getMetrics().CONNECTION_AUTHORIZED.add(1);
            } else {
                ServerMetrics.getMetrics().CONNECTION_UNAUTHORIZED.add(1);
            }
        }

        return new AuthorizationResult(authorized, shadowEnabled, authorizedId);
    }

    @Override
    public boolean isAdmin(final Identities identities) {
        if (identities == null || identities.getIds().size() == 0) {
            return false;
        }

        for (Identity identity : identities.getIds()) {
            if (permissions.containsKey(identity)) {
                int permission = permissions.get(identity);
                if ((permission & ZooDefs.Perms.ADMIN) == ZooDefs.Perms.ADMIN) {
                    LOG.info("isAdmin: Identity {} perm {} has admin bit", identity.toString(), permission);
                    // if ANY identity is an admin return true.  TODO: consider stricter model of ALL identities?
                    return true;
                } else {
                    LOG.info("isAdmin: Identity {} perm {} does not have admin bit", identity.toString(), permission);
                }
            } else {
                LOG.info("isAdmin: Identity {} not registered", identity.toString());
            }
        }
        return false;
    }

    private void updateAclsFromDataTree() {
        try {
            DataNode node = zkDb.getNode(aclZookeeper);
            if (node == null) {
                // clear acls if any have been set.
                if (aclCRC != -1) {
                    LOG.info("No acls found at path " + aclZookeeper + ", clearing acls.");
                    clearConfigs();
                    aclCRC = -1;
                }
                return;
            }

            byte[] data;
            synchronized (node) {
                data = node.getData();
            }

            CRC32 crc = new CRC32();
            crc.update(data);

            if (aclCRC != crc.getValue()) {
                ACLConfigs aclConfigs = mapper.readValue(new String(data, StandardCharsets.UTF_8), ACLConfigs.class);
                updateConfigs(aclConfigs.getAcl(), aclConfigs.isShadow());
                aclCRC = crc.getValue();
                LOG.info("Successfully updated permissions.");
            }
        } catch (Throwable t) {
            ServerMetrics.getMetrics().UPDATE_AUTHORIZATION_FAILED.add(1);
            LOG.error("Error loading acl configs.", t);
        }
    }

    private synchronized void updateConfigs(final Collection<ACLConfig> acls, boolean isShadow) {
        final Map<Identity, Integer> perms = new HashMap<>();

        for (ACLConfig config: acls) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("ACLConfig {}", config);
            }
            for (Identity identity: config.getIdentities()) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("identity \"{}\"", identity.toString());
                }
                if (perms.containsKey(identity)) {
                    perms.put(identity, perms.get(identity) | config.getPermission());
                } else {
                    perms.put(identity, config.getPermission());
                }
            }
        }

        permissions.putAll(perms);

        // Update shadow setting after adding newly-authorized identities,
        // but before removing old (no-longer-authorized) identities.
        // This is to prevent unnecessarily rejecting some identity in the
        // middle of an acl update (when "shadow" setting is changed).
        shadow.set(isShadow);

        permissions.entrySet().removeIf(e -> !perms.containsKey(e.getKey()));
    }

    private synchronized void clearConfigs() {
        shadow.set(true);
        permissions.clear();
    }

    public interface ACLAuthorizationConfigMXBean {
        public String getRejectNullIdentity();

        public String getRejectWithoutAclDefinition();

        public String getForceShadowMode();

        public void setRejectNullIdentity(String rejectNullIdentity);

        public void setRejectWithoutAclDefinition(String rejectWithoutAclDefinition);

        public void setForceShadowMode(String forceShadowMode);

        public void clearACLConfigs();
    }

    public class ACLAuthorizationConfigBean implements ACLAuthorizationConfigMXBean, ZKMBeanInfo {
        private final String name;

        public ACLAuthorizationConfigBean() {
            name = "ACLAuthorizationConfig";
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public boolean isHidden() {
            return false;
        }

        @Override
        public String getRejectNullIdentity() {
            return String.valueOf(ACLAuthorizationProvider.rejectNullIdentity);
        }

        @Override
        public String getRejectWithoutAclDefinition() {
            return String.valueOf(ACLAuthorizationProvider.rejectWithoutAclDefinition);
        }

        @Override
        public String getForceShadowMode() {
            return String.valueOf(ACLAuthorizationProvider.forceShadowMode);
        }

        @Override
        public void setRejectNullIdentity(String rejectNullIdentity) {
            ACLAuthorizationProvider.rejectNullIdentity = Boolean.parseBoolean(rejectNullIdentity);
        }

        @Override
        public void setRejectWithoutAclDefinition(String rejectWithoutAclDefinition) {
            ACLAuthorizationProvider.rejectWithoutAclDefinition = Boolean.parseBoolean(rejectWithoutAclDefinition);
        }

        @Override
        public void setForceShadowMode(String forceShadowMode) {
            ACLAuthorizationProvider.forceShadowMode = Boolean.parseBoolean(forceShadowMode);
        }

        @Override
        public void clearACLConfigs() {
            clearConfigs();
            LOG.info("Cleared ACLs through JMX.");
        }
    }

}
