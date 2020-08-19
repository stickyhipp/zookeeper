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

package org.apache.zookeeper.version.util;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.zookeeper.server.ExitCode;

@SuppressFBWarnings("DM_EXIT")
public class VerGen {

    private static final String PACKAGE_NAME = "org.apache.zookeeper.version";
    private static final String VERSION_CLASS_NAME = "VersionInfoMain";
    private static final String VERSION_INTERFACE_NAME = "Info";

    static void printUsage() {
        System.out.print("Usage:\tjava  -cp <classpath> org.apache.zookeeper."
                         + "version.util.VerGen maj.min.micro[-qualifier] rev buildDate outputDirectory");
        System.exit(ExitCode.UNEXPECTED_ERROR.getValue());
    }

    public static void generateFile(File outputDir, Version version, String rev, String buildDate) {
        String path = PACKAGE_NAME.replaceAll("\\.", "/");
        File pkgdir = new File(outputDir, path);
        if (!pkgdir.exists()) {
            // create the pkg directory
            boolean ret = pkgdir.mkdirs();
            if (!ret) {
                System.out.println("Cannnot create directory: " + path);
                System.exit(ExitCode.UNEXPECTED_ERROR.getValue());
            }
        } else if (!pkgdir.isDirectory()) {
            // not a directory
            System.out.println(path + " is not a directory.");
            System.exit(ExitCode.UNEXPECTED_ERROR.getValue());
        }

        try (FileWriter w = new FileWriter(new File(pkgdir, VERSION_INTERFACE_NAME + ".java"))) {
            w.write("// Do not edit!\n// File generated by org.apache.zookeeper" + ".version.util.VerGen.\n");
            w.write("/**\n");
            w.write("* Licensed to the Apache Software Foundation (ASF) under one\n");
            w.write("* or more contributor license agreements.  See the NOTICE file\n");
            w.write("* distributed with this work for additional information\n");
            w.write("* regarding copyright ownership.  The ASF licenses this file\n");
            w.write("* to you under the Apache License, Version 2.0 (the\n");
            w.write("* \"License\"); you may not use this file except in compliance\n");
            w.write("* with the License.  You may obtain a copy of the License at\n");
            w.write("*\n");
            w.write("*     http://www.apache.org/licenses/LICENSE-2.0\n");
            w.write("*\n");
            w.write("* Unless required by applicable law or agreed to in writing, software\n");
            w.write("* distributed under the License is distributed on an \"AS IS\" BASIS,\n");
            w.write("* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n");
            w.write("* See the License for the specific language governing permissions and\n");
            w.write("* limitations under the License.\n");
            w.write("*/\n");
            w.write("\n");
            w.write("package " + PACKAGE_NAME + ";\n\n");
            w.write("public interface " + VERSION_INTERFACE_NAME + " {\n");
            w.write("    int MAJOR=" + version.maj + ";\n");
            w.write("    int MINOR=" + version.min + ";\n");
            w.write("    int MICRO=" + version.micro + ";\n");
            w.write("    String QUALIFIER=" + (version.qualifier == null ? "\"\"" : "\"" + version.qualifier + "\"") + ";\n");
            if (rev.equals("-1")) {
                System.out.println("Unknown REVISION number, using " + rev);
            }
            w.write("    String REVISION_HASH=\"" + rev + "\";\n");
            w.write("    String BUILD_DATE=\"" + buildDate + "\";\n");
            w.write("}\n");
        } catch (IOException e) {
            System.out.println("Unable to generate version.Info file: " + e.getMessage());
            System.exit(ExitCode.UNEXPECTED_ERROR.getValue());
        }

        // Generate a main class to display version data
        // that can be exec'd in zkServer.sh
        try (FileWriter w = new FileWriter(new File(pkgdir, VERSION_CLASS_NAME + ".java"))) {
            w.write("// Do not edit!\n// File generated by org.apache.zookeeper" + ".version.util.VerGen.\n");
            w.write("/**\n");
            w.write("* Licensed to the Apache Software Foundation (ASF) under one\n");
            w.write("* or more contributor license agreements.  See the NOTICE file\n");
            w.write("* distributed with this work for additional information\n");
            w.write("* regarding copyright ownership.  The ASF licenses this file\n");
            w.write("* to you under the Apache License, Version 2.0 (the\n");
            w.write("* \"License\"); you may not use this file except in compliance\n");
            w.write("* with the License.  You may obtain a copy of the License at\n");
            w.write("*\n");
            w.write("*     http://www.apache.org/licenses/LICENSE-2.0\n");
            w.write("*\n");
            w.write("* Unless required by applicable law or agreed to in writing, software\n");
            w.write("* distributed under the License is distributed on an \"AS IS\" BASIS,\n");
            w.write("* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n");
            w.write("* See the License for the specific language governing permissions and\n");
            w.write("* limitations under the License.\n");
            w.write("*/\n");
            w.write("\n");
            w.write("package " + PACKAGE_NAME + ";\n\n");
            w.write("public class " + VERSION_CLASS_NAME + " implements " + PACKAGE_NAME + ".Info {\n");
            w.write("    public static void main(String[] args) {\n");
            w.write("        final String VER_STRING = MAJOR + \".\" + MINOR + \".\" + MICRO +");
            w.write("            (QUALIFIER == null ? \"\" : \"-\" + QUALIFIER)  + \" \" +");
            w.write("            BUILD_DATE;" + "\n");
            w.write("        System.out.println(\"Apache ZooKeeper, version \" + VER_STRING);\n");
            w.write("    }\n");
            w.write("}\n");
        } catch (IOException e) {
            System.out.println("Unable to generate version.VersionInfoMain file: " + e.getMessage());
            System.exit(ExitCode.UNEXPECTED_ERROR.getValue());
        }
    }

    public static class Version {

        public int maj;
        public int min;
        public int micro;
        public String qualifier;

    }

    public static Version parseVersionString(String input) {
        Version result = new Version();

        Pattern p = Pattern.compile("^(\\d+)\\.(\\d+)\\.(\\d+)((\\.\\d+)*)(-(.+))?$");
        Matcher m = p.matcher(input);

        if (!m.matches()) {
            return null;
        }
        result.maj = Integer.parseInt(m.group(1));
        result.min = Integer.parseInt(m.group(2));
        result.micro = Integer.parseInt(m.group(3));
        if (m.groupCount() == 7) {
            result.qualifier = m.group(7);
        } else {
            result.qualifier = null;
        }
        return result;
    }

    /**
     * Emits a org.apache.zookeeper.version.Info interface file with version and
     * revision information constants set to the values passed in as command
     * line parameters. The file is created in the current directory. <br>
     * Usage: java org.apache.zookeeper.version.util.VerGen maj.min.micro[-qualifier]
     * rev buildDate
     *
     * @param args
     *            <ul>
     *            <li>maj - major version number
     *            <li>min - minor version number
     *            <li>micro - minor minor version number
     *            <li>qualifier - optional qualifier (dash followed by qualifier text)
     *            <li>rev - current Git revision number
     *            <li>buildDate - date the build
     *            </ul>
     */
    public static void main(String[] args) {
        if (args.length != 4) {
            printUsage();
        }
        try {
            Version version = parseVersionString(args[0]);
            if (version == null) {
                System.err.println("Invalid version number format, must be \"x.y.z(-.*)?\"");
                System.exit(ExitCode.UNEXPECTED_ERROR.getValue());
            }
            String rev = args[1];
            if (rev == null || rev.trim().isEmpty()) {
                rev = "-1";
            } else {
                rev = rev.trim();
            }
            generateFile(new File(args[3]), version, rev, args[2]);
        } catch (NumberFormatException e) {
            System.err.println("All version-related parameters must be valid integers!");
            throw e;
        }
    }

}
