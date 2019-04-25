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

import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.test.TestUtils;
import org.apache.zookeeper.jmx.MBeanRegistry;
import org.apache.zookeeper.metrics.MetricsUtils;
import org.apache.zookeeper.server.DataTree;
import org.apache.zookeeper.server.ServerMetrics;
import org.apache.zookeeper.server.ZKDatabase;
import org.apache.zookeeper.test.JMXEnv;
import org.apache.zookeeper.test.QuorumUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import javax.management.Attribute;
import javax.management.ObjectName;


public class AuthorizationTest {
    private static ZKDatabase zkDb;
    private static DataTree dt;
    private static AuthorizationProvider provider;

    public static final String aclJson = "{" +
            "  \"acl\" : [ {" +
            "    \"aclType\" : \"ensemble\"," +
            "    \"permission\" : 1," +
            "    \"identities\" : [ " +
            "      {\"type\": \"user\", \"name\":\"test_user\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"test_service\"}" +
            "    ]" +
            "  }, {" +
            "    \"aclType\" : \"ensemble\"," +
            "    \"permission\" : 1," +
            "    \"identities\" : [" +
            "      {\"type\": \"user\", \"name\":\"test_user_1\"}," +
            "      {\"type\": \"user\", \"name\":\"test_user_2\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_a\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_b\"}" +
            "    ]" +
            "  } ]," +
            "  \"shadow\" : false" +
            "}";

    public static final String updatedAclJson = "{" +
            "  \"acl\" : [ {" +
            "    \"aclType\" : \"ensemble\"," +
            "    \"permission\" : 1," +
            "    \"identities\" : [ " +
            "      {\"type\": \"user\", \"name\":\"test_user_shadow\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"test_service_shadow\"}" +
            "    ]" +
            "  }, {" +
            "    \"aclType\" : \"ensemble\"," +
            "    \"permission\" : 1," +
            "    \"identities\" : [" +
            "      {\"type\": \"user\", \"name\":\"test_user_1\"}," +
            "      {\"type\": \"user\", \"name\":\"test_user_2\"}," +
            "      {\"type\": \"user\", \"name\":\"test_user_3\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_b\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_c\"}" +
            "    ]" +
            "  }, {" +
            "    \"aclType\" : \"ensemble\"," +
            "    \"permission\" : 2," +
            "    \"identities\" : [" +
            "      {\"type\": \"user\", \"name\":\"test_user_1\"}," +
            "      {\"type\": \"user\", \"name\":\"test_user_2\"}," +
            "      {\"type\": \"user\", \"name\":\"test_user_3\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_b\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_c\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_d\"}" +
            "    ]" +
            "  } ]," +
            "  \"shadow\" : false" +
            "}";

    public static final String shadowAclJson = "{" +
            "  \"acl\" : [ {\n" +
            "    \"aclType\" : \"ensemble\"," +
            "    \"permission\" : 2," +
            "    \"identities\" : [" +
            "      {\"type\": \"user\", \"name\":\"test_user_1\"}," +
            "      {\"type\": \"user\", \"name\":\"test_user_2\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_a\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_b\"}" +
            "    ]" +
            "  } ]," +
            "  \"shadow\" : true" +
            "}";

    public static final String noAclJson = "{\"acl\":[], \"shadow\":false}";

    public static final String[] badAcls = new String[]{
            "{\"acl\" : [ {" +
                    "    \"aclType\" : \"ensemble\"," +
                    "    \"permission\" : 1," +
                    "    \"identities\" : [ " +
                    "      {\"type\": \"user\", \"name\":\"test_user\"}," +
                    "      {\"type\": \"service_identity\", \"name\":\"test_service\"}" +
                    "    ]" +
                    "  }, {" +
                    "    \"aclType\" : \"ensemble\"," +
                    "    \"permission\" : 1," +
                    "    \"identities\" : [" +
                    "      {\"type\": \"user\", \"name\":\"test_user_3\"}," +
                    "      {\"type\": \"user\", \"name\":\"test_user_4\"}," +
                    "      {\"type\": \"bad_type\", \"name\":\"service_a\"}," +
                    "      {\"type\": \"service_identity\", \"name\":\"service_b\"}" +
                    "    ]" +
                    "  } ]," +
                    "  \"shadow\" : false" +
                    "}",
            "  {\"acl\" : [ {" +
                    "    \"aclType\" : \"unknown\"," +
                    "    \"permission\" : 2," +
                    "    \"identities\" : [" +
                    "      {\"type\": \"user\", \"name\":\"test_user_1\"}," +
                    "      {\"type\": \"service_identity\", \"name\":\"service\"}" +
                    "    ]" +
                    "  } ]," +
                    "  \"shadow\" : true" +
                    "}",
            "  {\"acl\" : [ {" +
                    "    \"aclType\" : \"ensemble\"," +
                    "    \"permission\" : 2," +
                    "    \"identities_with_typo\" : [" +
                    "      {\"type\": \"user\", \"name\":\"test_user\"}," +
                    "      {\"type\": \"service_identity\", \"name\":\"service\"}" +
                    "    ]" +
                    "  } ]," +
                    "  \"shadow\" : false" +
                    "}",
    };

    @BeforeClass
    public static void setUpClass() throws Exception {
        zkDb = new ZKDatabase(null);
        dt = zkDb.getDataTree();
        // create acl
        dt.createNode("/zookeeper/auth", null, null, 0, 0, 0, 0);
        provider = new ACLAuthorizationProvider(zkDb, 100);
    }

    @Before
    public void setup() throws KeeperException.NodeExistsException, KeeperException.NoNodeException {
        // reset permissions to aclJson
        if (dt.getNode(ACLAuthorizationProvider.aclZookeeper) == null) {
            dt.createNode(ACLAuthorizationProvider.aclZookeeper, aclJson.getBytes(), null, 0, 0, 0, 0);
        } else {
            dt.setData(ACLAuthorizationProvider.aclZookeeper, aclJson.getBytes(), 0, 0, 0);
        }
    }

    @Test
    public void testAuthorization() throws Exception {
        Identities user1 = new Identities("user:test_user_1");
        Identities user2 = new Identities("user:test_user_2");
        Identities user3 = new Identities("user:test_user_3");
        Identities user4 = new Identities("user:test_user_4");
        Identities svca = new Identities("svc:service_a");
        Identities svcb = new Identities("svc:service_b");
        Identities svcc = new Identities("svc:service_c");
        Identities svcd = new Identities("svc:service_d");
        Identities user4svca = new Identities("user:test_user_4,svc:service_a");

        // verify result based on original acls.
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user1).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user2).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user3).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user4).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svca).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcb).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcc).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcd).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user4svca).isAccepted();
        }, true, 1000);

        Assert.assertEquals(user1.getIds().get(0), provider.checkConnectPermission(user1).authorizedId);
        Assert.assertNull(provider.checkConnectPermission(user3).authorizedId);
        Assert.assertEquals(svca.getIds().get(0), provider.checkConnectPermission(svca).authorizedId);
        Assert.assertNull(provider.checkConnectPermission(svcc).authorizedId);
        Assert.assertEquals(svca.getIds().get(0), provider.checkConnectPermission(user4svca).authorizedId);

        // now update acls and test again
        dt.setData(ACLAuthorizationProvider.aclZookeeper, updatedAclJson.getBytes(), 0, 0, 0);

        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user1).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user2).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user3).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user4).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svca).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcb).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcc).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcd).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user4svca).isAccepted();
        }, false, 1000);

        Assert.assertEquals(user3.getIds().get(0), provider.checkConnectPermission(user3).authorizedId);
        Assert.assertNull(provider.checkConnectPermission(svca).authorizedId);
        Assert.assertNull(provider.checkConnectPermission(user4svca).authorizedId);
    }

    @Test
    public void testShadowAuthorization() throws Exception {
        dt.setData(ACLAuthorizationProvider.aclZookeeper, shadowAclJson.getBytes(), 0, 0, 0);

        Identities user3 = new Identities("user:test_user_3");
        Identities user4 = new Identities("user:test_user_4");
        Identities svccd = new Identities("svc:service_c,svc:service_d");
        Identities svcany = new Identities("any_service");

        List<Identities> identities = Arrays.asList(user3, user4, svccd, svcany);

        for (Identities ids : identities) {
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(ids).isAccepted();
            }, true, 1000);
        }
    }

    @Test
    public void testEmptyACL() throws Exception {
        dt.setData(ACLAuthorizationProvider.aclZookeeper, noAclJson.getBytes(), 0, 0, 0);

        Identities user1 = new Identities("user:test_user_1");
        Identities user2 = new Identities("user:test_user_2");
        Identities user3 = new Identities("user:test_user_3");
        Identities user4 = new Identities("user:test_user_4");
        Identities svca = new Identities("svc:service_a");
        Identities svcb = new Identities("svc:service_b");
        Identities svcc = new Identities("svc:service_c");
        Identities svcd = new Identities("svc:service_d");
        List<Identities> identities = Arrays.asList(user1, user2, user3, user4, svca, svcb, svcc, svcd);

        for (Identities ids : identities) {
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(ids).isAccepted();
            }, true, 1000);
        }

        ACLAuthorizationProvider.rejectWithoutAclDefinition = true;

        for (Identities ids : identities) {
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(ids).isAccepted();
            }, false, 1000);
        }
    }

    @Test
    public void testACLWithBadType() throws Exception {
        Identities user1 = new Identities("user:test_user_1");
        Identities user2 = new Identities("user:test_user_2");
        Identities user3 = new Identities("user:test_user_3");
        Identities user4 = new Identities("user:test_user_4");
        Identities svca = new Identities("svc:service_a");
        Identities svcb = new Identities("svc:service_b");
        Identities svcc = new Identities("svc:service_c");
        Identities svcd = new Identities("svc:service_d");

        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user1).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user2).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user3).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user4).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svca).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcb).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcc).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcd).isAccepted();
        }, false, 1000);

        for (int i = 0; i < badAcls.length; i++) {
            dt.setData(ACLAuthorizationProvider.aclZookeeper, badAcls[i].getBytes(), 0, 0, 0);
            ServerMetrics.getMetrics().resetAll();

            TestUtils.assertTimeout(() -> {
                long count = (long) MetricsUtils.currentServerMetrics().get("update_authorization_failed");
                return count > 0;
            }, true, 1000);

            // result should stay the same.
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(user1).isAccepted();
            }, true, 1000);
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(user2).isAccepted();
            }, true, 1000);
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(user3).isAccepted();
            }, false, 1000);
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(user4).isAccepted();
            }, false, 1000);
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(svca).isAccepted();
            }, true, 1000);
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(svcb).isAccepted();
            }, true, 1000);
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(svcc).isAccepted();
            }, false, 1000);
            TestUtils.assertTimeout(() -> {
                return provider.checkConnectPermission(svcd).isAccepted();
            }, false, 1000);
        }
    }

    @Test
    public void testJMXACLAuthorizationConfigBean() throws Exception {
        Identities user1 = new Identities("user:test_user_1");
        Identities user3 = new Identities("user:test_user_3");
        Identities svca = new Identities("svc:service_a");
        Identities svcc = new Identities("svc:service_c");

        JMXEnv.setUp();
        // locate acl authorization config bean
        ObjectName aclConfigBean = null;
        for (ObjectName bean : JMXEnv.conn().queryNames(new ObjectName(MBeanRegistry.DOMAIN + ":*"), null)) {
            if (bean.getCanonicalName().contains("ACLAuthorizationConfig")) {
                aclConfigBean = bean;
                break;
            }
        }
        Assert.assertNotNull("ACLAuthorizationConfig bean must not be null", aclConfigBean);

        // test reject null identity
        Assert.assertFalse(ACLAuthorizationProvider.rejectNullIdentity);
        String rejectNullIdentity = (String) JMXEnv.conn().getAttribute(aclConfigBean, "RejectNullIdentity");
        Assert.assertEquals("false", rejectNullIdentity);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(null).isAccepted();
        }, true, 1000);

        JMXEnv.conn().setAttribute(aclConfigBean, new Attribute("RejectNullIdentity", "true"));
        Assert.assertTrue(ACLAuthorizationProvider.rejectNullIdentity);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(null).isAccepted();
        }, false, 1000);

        // test force shadow mode
        Assert.assertFalse(ACLAuthorizationProvider.forceShadowMode);
        String forceShadowMode = (String) JMXEnv.conn().getAttribute(aclConfigBean, "ForceShadowMode");
        Assert.assertEquals("false", forceShadowMode);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user1).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user3).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svca).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcc).isAccepted();
        }, false, 1000);

        JMXEnv.conn().setAttribute(aclConfigBean, new Attribute("ForceShadowMode", "true"));
        Assert.assertTrue(ACLAuthorizationProvider.forceShadowMode);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user1).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user3).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svca).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcc).isAccepted();
        }, true, 1000);

        // turn off forceShadowMode first
        JMXEnv.conn().setAttribute(aclConfigBean, new Attribute("ForceShadowMode", "false"));
        Assert.assertFalse(ACLAuthorizationProvider.forceShadowMode);

        // test reject without acl definition
        Assert.assertFalse(ACLAuthorizationProvider.rejectWithoutAclDefinition);
        String rejectWithoutAclDefinition = (String) JMXEnv.conn().getAttribute(aclConfigBean, "RejectWithoutAclDefinition");
        Assert.assertEquals("false", rejectWithoutAclDefinition);

        dt.setData(ACLAuthorizationProvider.aclZookeeper, noAclJson.getBytes(), 0, 0, 0);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user1).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcc).isAccepted();
        }, true, 1000);

        JMXEnv.conn().setAttribute(aclConfigBean, new Attribute("RejectWithoutAclDefinition", "true"));
        Assert.assertTrue(ACLAuthorizationProvider.rejectWithoutAclDefinition);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user1).isAccepted();
        }, false, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcc).isAccepted();
        }, false, 1000);

        // test clear acl configs
        // clearing also sets shadow to true.
        JMXEnv.conn().invoke(aclConfigBean, "clearACLConfigs", new Object[0], new String[0]);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(user1).isAccepted();
        }, true, 1000);
        TestUtils.assertTimeout(() -> {
            return provider.checkConnectPermission(svcc).isAccepted();
        }, true, 1000);
    }

}
