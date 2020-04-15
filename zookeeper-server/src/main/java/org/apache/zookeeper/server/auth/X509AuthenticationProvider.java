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

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import org.apache.zookeeper.KeeperException;
import org.apache.zookeeper.common.ClientX509Util;
import org.apache.zookeeper.common.X509Exception.KeyManagerException;
import org.apache.zookeeper.common.X509Exception.TrustManagerException;
import org.apache.zookeeper.common.X509Util;
import org.apache.zookeeper.common.ZKConfig;
import org.apache.zookeeper.data.Id;
import org.apache.zookeeper.server.ServerCnxn;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An AuthenticationProvider backed by an X509TrustManager and an X509KeyManager
 * to perform remote host certificate authentication. The default algorithm is
 * SunX509 and a JKS KeyStore. To specify the locations of the key store and
 * trust store, set the following system properties:
 * <br><code>zookeeper.ssl.keyStore.location</code>
 * <br><code>zookeeper.ssl.trustStore.location</code>
 * <br>To specify store passwords, set the following system properties:
 * <br><code>zookeeper.ssl.keyStore.password</code>
 * <br><code>zookeeper.ssl.trustStore.password</code>
 * <br>Alternatively, this can be plugged with any X509TrustManager and
 * X509KeyManager implementation.
 */
public class X509AuthenticationProvider implements AuthenticationProvider {

    public static final String SCHEME = "x509";

    private static final String ZOOKEEPER_X509AUTHENTICATIONPROVIDER_SUPERUSER = "zookeeper.X509AuthenticationProvider.superUser";
    private static final Logger LOG = LoggerFactory.getLogger(X509AuthenticationProvider.class);
    private final X509TrustManager trustManager;
    private final X509KeyManager keyManager;

    /**
     * Initialize the X509AuthenticationProvider with a JKS KeyStore and JKS
     * TrustStore according to the following system properties:
     * <br><code>zookeeper.ssl.keyStore.location</code>
     * <br><code>zookeeper.ssl.trustStore.location</code>
     * <br><code>zookeeper.ssl.keyStore.password</code>
     * <br><code>zookeeper.ssl.trustStore.password</code>
     */
    public X509AuthenticationProvider() {
        ZKConfig config = new ZKConfig();
        try (X509Util x509Util = new ClientX509Util()) {
            String keyStoreLocation = config.getProperty(x509Util.getSslKeystoreLocationProperty(), "");
            String keyStorePassword = config.getProperty(x509Util.getSslKeystorePasswdProperty(), "");
            String keyStoreTypeProp = config.getProperty(x509Util.getSslKeystoreTypeProperty());

            boolean crlEnabled = Boolean.parseBoolean(config.getProperty(x509Util.getSslCrlEnabledProperty()));
            boolean ocspEnabled = Boolean.parseBoolean(config.getProperty(x509Util.getSslOcspEnabledProperty()));
            boolean hostnameVerificationEnabled = Boolean.parseBoolean(config.getProperty(x509Util.getSslHostnameVerificationEnabledProperty()));

            X509KeyManager km = null;
            X509TrustManager tm = null;
            if (keyStoreLocation.isEmpty()) {
                LOG.warn("keystore not specified for client connection");
            } else {
                try {
                    km = X509Util.createKeyManager(keyStoreLocation, keyStorePassword, keyStoreTypeProp);
                } catch (KeyManagerException e) {
                    LOG.error("Failed to create key manager", e);
                }
            }

            String trustStoreLocation = config.getProperty(x509Util.getSslTruststoreLocationProperty(), "");
            String trustStorePassword = config.getProperty(x509Util.getSslTruststorePasswdProperty(), "");
            String trustStoreTypeProp = config.getProperty(x509Util.getSslTruststoreTypeProperty());

            if (trustStoreLocation.isEmpty()) {
                LOG.warn("Truststore not specified for client connection");
            } else {
                try {
                    tm = X509Util.createTrustManager(
                        trustStoreLocation,
                        trustStorePassword,
                        trustStoreTypeProp,
                        crlEnabled,
                        ocspEnabled,
                        hostnameVerificationEnabled,
                        false);
                } catch (TrustManagerException e) {
                    LOG.error("Failed to create trust manager", e);
                }
            }
            this.keyManager = km;
            this.trustManager = tm;
        }
    }

    /**
     * Initialize the X509AuthenticationProvider with the provided
     * X509TrustManager and X509KeyManager.
     *
     * @param trustManager X509TrustManager implementation to use for remote
     *                     host authentication.
     * @param keyManager   X509KeyManager implementation to use for certificate
     *                     management.
     */
    public X509AuthenticationProvider(X509TrustManager trustManager, X509KeyManager keyManager) {
        this.trustManager = trustManager;
        this.keyManager = keyManager;
    }

    @Override
    public String getScheme() {
        return SCHEME;
    }

    /**
     * Extract the clientId from the ServerCnxn client cert chain.
     *
     * @param cnxn - ServerCnxn
     * @return client id
     * @throws KeeperException
     */
    private String getClientId(ServerCnxn cnxn) throws KeeperException {
        Certificate[] certChain = cnxn.getClientCertificateChain();

        if (certChain == null || certChain.length == 0) {
            throw new KeeperException.AuthFailedException();
        }

        // Java arrays are reified, so we can't simply cast a
        // Certificate[] to a X509Certificate[], even if all the
        // elements in the Certificate[] are of type X509Certificate.
        // We have to make a new array and copy all the elements.
        X509Certificate[] x509CertChain = new X509Certificate[certChain.length];
        for (int i = 0; i < certChain.length; i++) {
            if (!(certChain[i] instanceof X509Certificate)) {
                LOG.error("Certificate {} is not a X509Certificate", certChain[i]);
                throw new KeeperException.AuthFailedException();
            }
            x509CertChain[i] = (X509Certificate) certChain[i];
        }

        if (trustManager == null) {
            LOG.error("No trust manager available to authenticate session 0x{}", Long.toHexString(cnxn.getSessionId()));
            throw new KeeperException.AuthFailedException();
        }

        X509Certificate clientCert = x509CertChain[0];

        try {
            // Authenticate client certificate
            trustManager.checkClientTrusted(x509CertChain,
                    clientCert.getPublicKey().getAlgorithm());
        } catch (CertificateException ce) {
            LOG.error("Failed to trust certificate for session 0x" + Long.toHexString(cnxn.getSessionId()), ce);
            throw new KeeperException.AuthFailedException();
        }
        return getClientId(clientCert);
    }

    protected void checkForSuper(ServerCnxn cnxn, String clientId, byte[] authData) throws KeeperException {
        if (matches(clientId, System.getProperty(ZOOKEEPER_X509AUTHENTICATIONPROVIDER_SUPERUSER))) {
            cnxn.addAuthInfo(new Id("super", clientId));
            LOG.info("Authenticated Id '{}' as super user", clientId);
        }
    }

    @Override
    public KeeperException.Code handleAuthentication(ServerCnxn cnxn, byte[] authData) {
        try {
            String clientId = getClientId(cnxn);
            checkForSuper(cnxn, clientId, authData);
            Id authInfo = new Id(getScheme(), clientId);
            cnxn.addAuthInfo(authInfo);

            LOG.debug("Authenticated Id '{}' for Scheme '{}'", authInfo.getId(), authInfo.getScheme());
            return KeeperException.Code.OK;
        } catch (Exception e) {
            LOG.error("Failed to authenticate session 0x{}", Long.toHexString(cnxn.getSessionId()), e);
            return KeeperException.Code.AUTHFAILED;
        }
    }

    /**
     * Determine the string to be used as the remote host session Id for
     * authorization purposes. Associate this client identifier with a
     * ServerCnxn that has been authenticated over SSL, and any ACLs that refer
     * to the authenticated client.
     *
     * @param clientCert Authenticated X509Certificate associated with the
     *                   remote host.
     * @return Identifier string to be associated with the client.
     */
    protected String getClientId(X509Certificate clientCert) {
        return clientCert.getSubjectX500Principal().getName();
    }

    @Override
    public boolean matches(String id, String aclExpr) {
        if (id == null || id.length() == 0 || aclExpr == null || aclExpr.length() == 0) {
            return false;
        }
        return (id.equals(aclExpr));
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public boolean isValid(String id) {
        try {
            new X500Principal(id);
            return true;
        } catch (IllegalArgumentException e) {
            LOG.warn("Error creating X500Principal for {}", id, e);
            return false;
        }
    }

    /**
     * Get the X509TrustManager implementation used for remote host
     * authentication.
     *
     * @return The X509TrustManager.
     * @throws TrustManagerException When there is no trust manager available.
     */
    public X509TrustManager getTrustManager() throws TrustManagerException {
        if (trustManager == null) {
            throw new TrustManagerException("No trust manager available");
        }
        return trustManager;
    }

    /**
     * Get the X509KeyManager implementation used for certificate management.
     *
     * @return The X509KeyManager.
     * @throws KeyManagerException When there is no key manager available.
     */
    public X509KeyManager getKeyManager() throws KeyManagerException {
        if (keyManager == null) {
            throw new KeyManagerException("No key manager available");
        }
        return keyManager;
    }

}
