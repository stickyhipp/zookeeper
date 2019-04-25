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

import org.junit.Assert;
import org.junit.Test;

public class IdentitiesTest {

    private static final String user1 = "user:test_user/dev123.example.com";
    private static final String user2 = "user:test_user_without_host";
    private static final String svc1 = "svc:zk-client";
    private static final String job1 = "job:some-job-name";
    private static final String host1 = "host:abc123.domain.com";
    private static final String host_tier1 = "host_tier:abc";

    private static final String malformed1 = "unknown:zk-client";
    private static final String malformed2 = "xyz:";
    private static final String malformed3 = "svc:multiple_colon:";
    private static final String malformed4 = "no-colon";

    private Identities ids = null;

    @Test
    public void testSingleIdentity() {
        ids = new Identities(user1);
        Assert.assertEquals(1, ids.getIds().size());
        Assert.assertEquals(Identity.Type.USER, ids.getIds().get(0).getType());
        Assert.assertEquals("test_user/dev123.example.com", ids.getIds().get(0).getName());
        Assert.assertEquals(user1, ids.getIds().get(0).toString());

        ids = new Identities(user2);
        Assert.assertEquals(1, ids.getIds().size());
        Assert.assertEquals(Identity.Type.USER, ids.getIds().get(0).getType());
        Assert.assertEquals("test_user_without_host", ids.getIds().get(0).getName());
        Assert.assertEquals(user2, ids.getIds().get(0).toString());

        ids = new Identities(svc1);
        Assert.assertEquals(1, ids.getIds().size());
        Assert.assertEquals(Identity.Type.SERVICE_IDENTITY, ids.getIds().get(0).getType());
        Assert.assertEquals("zk-client", ids.getIds().get(0).getName());
        Assert.assertEquals(svc1, ids.getIds().get(0).toString());

        ids = new Identities(job1);
        Assert.assertEquals(1, ids.getIds().size());
        Assert.assertEquals(Identity.Type.JOB, ids.getIds().get(0).getType());
        Assert.assertEquals("some-job-name", ids.getIds().get(0).getName());
        Assert.assertEquals(job1, ids.getIds().get(0).toString());

        ids = new Identities(host1);
        Assert.assertEquals(1, ids.getIds().size());
        Assert.assertEquals(Identity.Type.HOST, ids.getIds().get(0).getType());
        Assert.assertEquals("abc123.domain.com", ids.getIds().get(0).getName());
        Assert.assertEquals(host1, ids.getIds().get(0).toString());

        ids = new Identities(host_tier1);
        Assert.assertEquals(1, ids.getIds().size());
        Assert.assertEquals(Identity.Type.HOST_TIER, ids.getIds().get(0).getType());
        Assert.assertEquals("abc", ids.getIds().get(0).getName());
        Assert.assertEquals(host_tier1, ids.getIds().get(0).toString());
    }

    @Test
    public void testMalformed() {
        ids = new Identities(malformed1);
        Assert.assertEquals(1, ids.getIds().size());
        Assert.assertEquals(Identity.Type.UNKNOWN_TYPE, ids.getIds().get(0).getType());
        Assert.assertEquals(malformed1, ids.getIds().get(0).getName());
        Assert.assertEquals(":" + malformed1, ids.getIds().get(0).toString());

        ids = new Identities(malformed2);
        Assert.assertEquals(1, ids.getIds().size());
        Assert.assertEquals(Identity.Type.UNKNOWN_TYPE, ids.getIds().get(0).getType());
        Assert.assertEquals(malformed2, ids.getIds().get(0).getName());
        Assert.assertEquals(":" + malformed2, ids.getIds().get(0).toString());

        ids = new Identities(malformed3);
        Assert.assertEquals(1, ids.getIds().size());
        Assert.assertEquals(Identity.Type.SERVICE_IDENTITY, ids.getIds().get(0).getType());
        Assert.assertEquals("multiple_colon:", ids.getIds().get(0).getName());
        Assert.assertEquals(malformed3, ids.getIds().get(0).toString());

        ids = new Identities(malformed4);
        Assert.assertEquals(1, ids.getIds().size());
        Assert.assertEquals(Identity.Type.UNKNOWN_TYPE, ids.getIds().get(0).getType());
        Assert.assertEquals(malformed4, ids.getIds().get(0).getName());
        Assert.assertEquals(":" + malformed4, ids.getIds().get(0).toString());
    }

    @Test
    public void testMixed() {
        String clientId = host1 + "," + user1 + "," + svc1;
        ids = new Identities(clientId);
        Assert.assertEquals(clientId, ids.toString());
        Assert.assertEquals(3, ids.getIds().size());

        Assert.assertEquals(Identity.Type.HOST, ids.getIds().get(0).getType());
        Assert.assertEquals("abc123.domain.com", ids.getIds().get(0).getName());
        Assert.assertEquals(host1, ids.getIds().get(0).toString());

        Assert.assertEquals(Identity.Type.USER, ids.getIds().get(1).getType());
        Assert.assertEquals("test_user/dev123.example.com", ids.getIds().get(1).getName());
        Assert.assertEquals(user1, ids.getIds().get(1).toString());

        Assert.assertEquals(Identity.Type.SERVICE_IDENTITY, ids.getIds().get(2).getType());
        Assert.assertEquals("zk-client", ids.getIds().get(2).getName());
        Assert.assertEquals(svc1, ids.getIds().get(2).toString());
    }

    @Test
    public void testMixedMalformed() {
        // malformed4 at the end, plus missing a comma between malformed2 and svc1
        String clientId = job1 + "," + malformed2 + svc1 + "," + user2 + "," + malformed4;
        ids = new Identities(clientId);
        Assert.assertEquals(clientId, ids.toString());
        Assert.assertEquals(4, ids.getIds().size());

        Assert.assertEquals(Identity.Type.JOB, ids.getIds().get(0).getType());
        Assert.assertEquals("some-job-name", ids.getIds().get(0).getName());
        Assert.assertEquals(job1, ids.getIds().get(0).toString());

        Assert.assertEquals(Identity.Type.UNKNOWN_TYPE, ids.getIds().get(1).getType());
        Assert.assertEquals(malformed2 + svc1, ids.getIds().get(1).getName());
        Assert.assertEquals(":" + malformed2 + svc1, ids.getIds().get(1).toString());

        Assert.assertEquals(Identity.Type.USER, ids.getIds().get(2).getType());
        Assert.assertEquals("test_user_without_host", ids.getIds().get(2).getName());
        Assert.assertEquals(user2, ids.getIds().get(2).toString());

        Assert.assertEquals(Identity.Type.UNKNOWN_TYPE, ids.getIds().get(3).getType());
        Assert.assertEquals(malformed4, ids.getIds().get(3).getName());
        Assert.assertEquals(":" + malformed4, ids.getIds().get(3).toString());
    }
}
