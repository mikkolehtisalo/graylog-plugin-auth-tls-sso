/**
 * This file is part of Graylog Archive.
 *
 * Graylog Archive is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Graylog Archive is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Graylog Archive.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.graylog.plugins.auth.tls.sso;

import com.google.common.collect.Maps;
import org.apache.shiro.authc.AuthenticationInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.glassfish.jersey.internal.util.collection.MultivaluedStringMap;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.security.PasswordAlgorithmFactory;
import org.graylog2.security.hashing.SHA1HashPasswordAlgorithm;
import org.graylog2.shared.security.HttpHeadersToken;
import org.graylog2.shared.security.Permissions;
import org.graylog2.shared.users.UserService;
import org.graylog2.users.RoleService;
import org.graylog2.users.UserImpl;
import org.jboss.netty.handler.ipfilter.IpSubnet;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;

import java.net.UnknownHostException;
import java.security.Security;
import java.util.Collections;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SsoAuthRealmTest {

    private String testCert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIGBzCCA++gAwIBAgIJANB03dewxWttMA0GCSqGSIb3DQEBCwUAMIGGMQswCQYD\n" +
            "VQQGEwJGSTEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0\n" +
            "IENvbXBhbnkgTHRkMRgwFgYDVQQDDA9NaWtrbyBMZWh0aXNhbG8xKDAmBgkqhkiG\n" +
            "9w0BCQEWGW1pa2tvLmxlaHRpc2Fsb0BnbWFpbC5jb20wHhcNMTYxMTIxMTk0MjUw\n" +
            "WhcNMTYxMjIxMTk0MjUwWjCBhjELMAkGA1UEBhMCRkkxFTATBgNVBAcMDERlZmF1\n" +
            "bHQgQ2l0eTEcMBoGA1UECgwTRGVmYXVsdCBDb21wYW55IEx0ZDEYMBYGA1UEAwwP\n" +
            "TWlra28gTGVodGlzYWxvMSgwJgYJKoZIhvcNAQkBFhltaWtrby5sZWh0aXNhbG9A\n" +
            "Z21haWwuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2ByaR6ok\n" +
            "Eaobgi/mGGaNFHy2X6nHYBZOih4yeKgZEUMdeKMJxTQForC7UYR2Z36SH866k6JQ\n" +
            "M8LReoWGro6+46Ouolh0EZzdPvcQrcd37jo/sraWBIQWsTNrdhQvl2QmPuNxRCPa\n" +
            "dw7+tUhSCRKp4ohMaNa2DSCe8jqm6J9+ArWbGwgi8s4qE4UZdBUgKnW6obMTsaYO\n" +
            "1cWnZ3YYUjOLuf1uUieqkjcA15hE+Hk03FYEbyDI5nZx1RmDh5qrVvravO5bJkjU\n" +
            "KMmEzOYL5BUC+TJFAdrTt2RCuyHREhSYMzvMEU+55D52UhMNrxiVPC7KAzOA7+2S\n" +
            "AqS/x26AI8DUvEed7gpfaS1GSlmP6n54rKgTTLyBKoOYLLWhrc0v64fqc7hSiGbO\n" +
            "4EGFZ3V1wpwVUsTCWzEhRkkyOhYL9WFBJFXuHggXd8dS7gMuJ4gZmli2EyXz3io4\n" +
            "R4wa1afY1RY+f241+NQ9jVjY8eDAge+zNgvMZQjxJrjrjqmyo4jxkfsbDSeMZkjQ\n" +
            "AXRcLDHz2oQY6mMQYB4bVMmNmdxKIlGWp/9kSci9dfr0s4WJxn7JgFzrM1nGoeqc\n" +
            "zqJsc8xQQNk4eBswS3AhaU+x18u5NtT2WyUpWr+Zp4vIZ0NQgn9KJU0ggI1TXwVF\n" +
            "H3QLJt+pWYGlF+MLvw3p+9n/TLe3B4ipaAMCAwEAAaN2MHQwHQYDVR0OBBYEFPbv\n" +
            "jI3QJyUx5IlP/LMBrPkJ6aAQMB8GA1UdIwQYMBaAFPbvjI3QJyUx5IlP/LMBrPkJ\n" +
            "6aAQMAwGA1UdEwQFMAMBAf8wJAYDVR0RBB0wG4EZbWlra28ubGVodGlzYWxvQGdt\n" +
            "YWlsLmNvbTANBgkqhkiG9w0BAQsFAAOCAgEAEfK/pSpEEPAd5Ppn5OcXRdLVpaZS\n" +
            "0Y82oaTKYUqVV1zLyzAq+XGRdL6Y4vq8hKXZoHDNNGiNfCEqKlMK8Y8u1vM/4pe0\n" +
            "FkyVaUAB1qxBsb9moG6b5+Q5IGi2dOZNMd0aLKzNk7GgVk3UZiEaf2FcffYDeBbu\n" +
            "5PFsii08laz4kd3afimM+6L7Kj2ks7EYyT/2TGQlYJSZerFzDmLKt+R/UmxNedAd\n" +
            "zKNGWhBHNOqKWpm5elIbsC3isipJVEPpeInl4eA1c3S0LcfNOHSjfqWjCWua6tVm\n" +
            "sbUGAtshUmbPvgiYUHIHz+WQY3UyCVd6TU4UT2JukciqSDnL3y7+icV1vmyO/kts\n" +
            "2pj0MYeV98h55n9gjLSzhQW41xQI3XbljnkMoDjNeGyRMfQHDft1LEuhThdLpmGS\n" +
            "SkM0KbzFcJvzKB/mk6Egfy+DAdAC/GvG1vsTk+exmQw33c/QJo8UXztF5ZX7Jpjk\n" +
            "mH7n3EEdFjXd5VB0UcRP9pt1l/5rhQA11Q4NDm+NU3+1RkbmRRfyKqTV4xTcK9AJ\n" +
            "mPvxGk+ImXK2remgz9E+jiQ59KSPLxDkYVyUkzCn7M0usxp1FuMFwop5YrvV1SGw\n" +
            "pIQfqbCL0HM1oFTQtB6g5YtwoFdqkJItHtUbGHrOs5QlcESDogZt8zaIqLTi3I/g\n" +
            "T6YwWRRqnGMhpWY=\n" +
            "-----END CERTIFICATE-----\n";

    // Make sure BC is loaded
    @BeforeClass
    public static void onceExecutedBeforeAll() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void checkSubnetConfig() throws UnknownHostException {

        Set<IpSubnet> trustedProxies = Collections.singleton(new IpSubnet("192.168.0.0/24"));
        final ClusterConfigService configService = mock(ClusterConfigService.class);

        when(configService.getOrDefault(any(), any()))
                .thenReturn(SsoAuthConfig.builder()
                                    .certificateHeader("tls-client-cert")
                                    .autoCreateUser(false)
                                    .requireTrustedProxies(false)
                                    .build());

        final UserService userService = mock(UserService.class);
        when(userService.load(eq("mikko.lehtisalo@gmail.com"))).thenReturn(new UserImpl(mock(PasswordAlgorithmFactory.class),
                                                                    mock(Permissions.class),
                                                                    Maps.newHashMap()));
        final SsoAuthRealm realm = new SsoAuthRealm(userService,
                                                    configService,
                                                    mock(RoleService.class),
                                                    trustedProxies);

        final MultivaluedStringMap headers = new MultivaluedStringMap();
        // headers must be lowercase, jersey does this the same way
        headers.put("tls-client-cert", Collections.singletonList(testCert));

        final HttpHeadersToken headersToken = new HttpHeadersToken(headers, "192.168.0.1", "192.168.0.1");
        final SsoAuthRealm realmSpy = Mockito.spy(realm);
        final AuthenticationInfo info = realmSpy.doGetAuthenticationInfo(headersToken);

        assertThat(info).isNotNull();
        assertThat(info.getPrincipals().getPrimaryPrincipal()).isNotNull();

        verify(userService).load(eq("mikko.lehtisalo@gmail.com"));
        verify(realmSpy, never()).inTrustedSubnets(anyString());
    }

    @Test
    public void testDefaultDomain() {

        final ClusterConfigService configService = mock(ClusterConfigService.class);

        when(configService.getOrDefault(any(), any()))
                .thenReturn(SsoAuthConfig.builder()
                                    .certificateHeader("tls-client-cert")
                                    .autoCreateUser(true)
                                    .requireTrustedProxies(false)
                                    .build());

        final UserService userService = mock(UserService.class);
        final UserImpl user = new UserImpl(
                new PasswordAlgorithmFactory(Collections.emptyMap(),
                                             new SHA1HashPasswordAlgorithm("1234567890")),
                mock(Permissions.class),
                Maps.newHashMap());
        when(userService.create()).thenReturn(user);

        final RoleService roleService = mock(RoleService.class);
        when(roleService.getReaderRoleObjectId()).thenReturn("57a1d276227c473674e1d997");
        final SsoAuthRealm realm = new SsoAuthRealm(userService,
                                                    configService,
                                                    roleService,
                                                    Collections.emptySet());

        final MultivaluedStringMap headers = new MultivaluedStringMap();
        // headers must be lowercase, jersey does this the same way
        headers.put("tls-client-cert", Collections.singletonList(testCert));
        final HttpHeadersToken headersToken = new HttpHeadersToken(headers, "192.168.0.1", "192.168.0.1");
        final SsoAuthRealm realmSpy = Mockito.spy(realm);
        final AuthenticationInfo info = realmSpy.doGetAuthenticationInfo(headersToken);

        assertThat(info).isNotNull();
        verify(userService).create();
        assertThat(user.getEmail()).isEqualTo("mikko.lehtisalo@gmail.com");
    }

    @Test
    public void testDefaultDomainNotSet() {

        final ClusterConfigService configService = mock(ClusterConfigService.class);

        when(configService.getOrDefault(any(), any()))
                .thenReturn(SsoAuthConfig.builder()
                                    .certificateHeader("tls-client-cert")
                                    .autoCreateUser(true)
                                    .requireTrustedProxies(false)
                                    .build());

        final UserService userService = mock(UserService.class);
        final UserImpl user = new UserImpl(
                new PasswordAlgorithmFactory(Collections.emptyMap(),
                                             new SHA1HashPasswordAlgorithm("1234567890")),
                mock(Permissions.class),
                Maps.newHashMap());
        when(userService.create()).thenReturn(user);

        final RoleService roleService = mock(RoleService.class);
        when(roleService.getReaderRoleObjectId()).thenReturn("57a1d276227c473674e1d997");
        final SsoAuthRealm realm = new SsoAuthRealm(userService,
                                                    configService,
                                                    roleService,
                                                    Collections.emptySet());

        final MultivaluedStringMap headers = new MultivaluedStringMap();
        // headers must be lowercase, jersey does this the same way
        headers.put("tls-client-cert", Collections.singletonList(testCert));
        final HttpHeadersToken headersToken = new HttpHeadersToken(headers, "192.168.0.1", "192.168.0.1");
        final SsoAuthRealm realmSpy = Mockito.spy(realm);
        final AuthenticationInfo info = realmSpy.doGetAuthenticationInfo(headersToken);

        assertThat(info).isNotNull();
        verify(userService).create();
        assertThat(user.getEmail()).isEqualTo("mikko.lehtisalo@gmail.com");
    }
}