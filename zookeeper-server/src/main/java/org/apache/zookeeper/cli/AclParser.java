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

package org.apache.zookeeper.cli;

import java.util.ArrayList;
import java.util.List;
import org.apache.zookeeper.ZooDefs;
import org.apache.zookeeper.data.ACL;
import org.apache.zookeeper.data.Id;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * a parser for ACL strings
 */
public class AclParser {

    private static final Logger LOG = LoggerFactory.getLogger(AclParser.class);

    /**
     * parse string into list of ACL
     * @param aclString
     * @return
     */
    public static List<ACL> parse(String aclString) {
        List<ACL> acls;
        /*
         * If a user want to set ACL which itself contains a comma, 
         * then they need to escape that comma (i.e. use "\," inplace of "," in zkcli)
         * 
         * A non escaped comma in the input is considered as the splitter between 2 ACL's
         * 
         * Ex:- setAcl /path x509:user:pass\,host:12345=:cdrwa,world:anyone:crdwa,
         * This command has 2 ACL's 
         * 1> x509:user:pass,host:12345=:cdrwa  -> Notice the escape character before, is auto removed
         * 2> world:anyone:crdwa
         */
        String[] aclStrings = aclString.split("(?<!\\\\),");
        
        acls = new ArrayList<ACL>();
        for (String aclWithEscapeCharacter : aclStrings) {
            // remove escape character before comma to form the correct ACL we need to use
            String acl = aclWithEscapeCharacter.replaceAll("\\\\,", ",");
            LOG.debug("acl escaped \"{}\"", acl);
            int firstColon = acl.indexOf(':');
            int lastColon = acl.lastIndexOf(':');
            if (firstColon == -1 || lastColon == -1 || firstColon == lastColon) {
                System.err.println(acl + " does not have the form scheme:id:perm");
                continue;
            }
            ACL newAcl = new ACL();
            newAcl.setId(new Id(acl.substring(0, firstColon), acl.substring(firstColon + 1, lastColon)));
            newAcl.setPerms(getPermFromString(acl.substring(lastColon + 1)));
            LOG.debug("acl processed \"{}\"", newAcl);
            acls.add(newAcl);
        }
        return acls;
    }

    private static int getPermFromString(String permString) {
        int perm = 0;
        for (int i = 0; i < permString.length(); i++) {
            switch (permString.charAt(i)) {
            case 'r':
                perm |= ZooDefs.Perms.READ;
                break;
            case 'w':
                perm |= ZooDefs.Perms.WRITE;
                break;
            case 'c':
                perm |= ZooDefs.Perms.CREATE;
                break;
            case 'd':
                perm |= ZooDefs.Perms.DELETE;
                break;
            case 'a':
                perm |= ZooDefs.Perms.ADMIN;
                break;
            default:
                System.err.println("Unknown perm type: " + permString.charAt(i));
            }
        }
        return perm;
    }

}
