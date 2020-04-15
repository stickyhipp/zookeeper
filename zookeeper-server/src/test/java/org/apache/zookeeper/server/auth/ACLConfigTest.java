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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.zookeeper.ZooDefs;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class ACLConfigTest {
    private static final ObjectMapper mapper = new ObjectMapper();

    private static final String aclJson = "{" +
            "  \"acl\" : [ {" +
            "    \"aclType\" : \"ensemble\"," +
            "    \"permission\" : 1," +
            "    \"identities\" : [ " +
            "      {\"type\": \"user\", \"name\":\"test_user\"}," +
            "      {\"name\":\"name_without_type\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"test_service\"}" +
            "    ]" +
            "  }, {" +
            "    \"aclType\" : \"ensemble\"," +
            "    \"permission\" : 2," +
            "    \"identities\" : [" +
            "      {\"type\": \"user\", \"name\":\"test_user_1\"}," +
            "      {\"type\": \"user\", \"name\":\"test_user_2\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_a\"}," +
            "      {\"type\": \"service_identity\", \"name\":\"service_b\"}" +
            "    ]" +
            "  } ]," +
            "  \"shadow\" : false" +
            "}";

    private static final String aclSingleUser = "{\"acl\":[{\"aclType\":\"ensemble\",\"identities\":[{\"name\":\"pwelch\",\"type\":\"user\"}],\"permission\":16}],\"shadow\":false}";


    @Test
    public void testSingleUserAcl() throws IOException {
        mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS, true);
        ACLAuthorizationProvider.ACLConfigs aclConfigs = mapper.readValue(aclSingleUser, ACLAuthorizationProvider.ACLConfigs.class);

        Assert.assertEquals(1, aclConfigs.getAcl().size());
        Assert.assertFalse(aclConfigs.isShadow());

        EnsembleACLConfig admin = (EnsembleACLConfig) aclConfigs.getAcl().get(0);
        Assert.assertEquals(ZooDefs.Perms.ADMIN, admin.getPermission());
        Assert.assertEquals(1, admin.getIdentities().size());
        Assert.assertEquals("user:pwelch", admin.getIdentities().get(0).toString());
    }

    @Test
    public void testSerialization() throws JsonProcessingException {
        ACLConfig config = new EnsembleACLConfig(ZooDefs.Perms.READ, Arrays.asList(
                new Identity(Identity.Type.USER, "test_user"),
                new Identity(null, "test_user"),
                new Identity(Identity.Type.SERVICE_IDENTITY, "test_service")));

        String result = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(config);

        Assert.assertTrue(result.contains("aclType") && result.contains("ensemble"));
        Assert.assertTrue(result.contains("permission") && result.contains(Integer.toString(ZooDefs.Perms.READ)));
        Assert.assertTrue(result.contains("identities") && result.contains(Identity.Type.USER.name()));
        Assert.assertTrue(result.contains("name") && result.contains("test_user"));
        Assert.assertTrue(result.contains("null") && result.contains("test_service"));

        Identity d1 = new Identity(null, "name_without_type");
        Identity d2 = new Identity(null, "name_without_type");
        Assert.assertTrue(d1 != d2 && d1.equals(d2));
    }

    @Test
    public void testDeserialization() throws IOException {
        mapper.configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS, true);
        ACLAuthorizationProvider.ACLConfigs aclConfigs = mapper.readValue(aclJson, ACLAuthorizationProvider.ACLConfigs.class);

        Assert.assertEquals(2,  aclConfigs.getAcl().size());
        Assert.assertFalse(aclConfigs.isShadow());

        EnsembleACLConfig read = (EnsembleACLConfig) aclConfigs.getAcl().get(0);
        Assert.assertEquals(ZooDefs.Perms.READ, read.getPermission());
        Assert.assertEquals(3, read.getIdentities().size());
        List<Identity> readList = Arrays.asList(
                new Identity(Identity.Type.USER, "test_user"),
                new Identity(null, "name_without_type"),
                new Identity(Identity.Type.SERVICE_IDENTITY, "test_service"));
        for (Identity identity: read.getIdentities()) {
            Assert.assertTrue(readList.contains(identity));
        }

        EnsembleACLConfig write = (EnsembleACLConfig) aclConfigs.getAcl().get(1);
        Assert.assertEquals(ZooDefs.Perms.WRITE, write.getPermission());
        Assert.assertEquals(4, write.getIdentities().size());
        List<Identity> writeList = Arrays.asList(
                new Identity(Identity.Type.USER, "test_user_1"),
                new Identity(Identity.Type.USER, "test_user_2"),
                new Identity(Identity.Type.SERVICE_IDENTITY, "service_a"),
                new Identity(Identity.Type.SERVICE_IDENTITY, "service_b"));
        for (Identity identity: write.getIdentities()) {
            Assert.assertTrue(writeList.contains(identity));
        }
    }

}
