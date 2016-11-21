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

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringReader;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameStyle;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;

public class CertificateTools {

    private static final Logger log = LoggerFactory.getLogger(CertificateTools.class);

    private static Map<String, String> extendedUsageOids;
    private static LoadingCache<String, UserInfo> userInfos;

    static {
        extendedUsageOids = new HashMap<>();
        extendedUsageOids.put("2.5.29.37.0", "All usages");
        extendedUsageOids.put("1.3.6.1.5.5.7.3.0", "All usages");
        extendedUsageOids.put("1.3.6.1.5.5.7.3.1", "Server authentication");
        extendedUsageOids.put("1.3.6.1.5.5.7.3.2", "Client authentication");
        extendedUsageOids.put("1.3.6.1.5.5.7.3.3", "Code signing");
        extendedUsageOids.put("1.3.6.1.5.5.7.3.4", "Email protection");
        extendedUsageOids.put("1.3.6.1.5.5.7.3.5", "IPSec end system");
        extendedUsageOids.put("1.3.6.1.5.5.7.3.6", "IPSec tunnel");
        extendedUsageOids.put("1.3.6.1.5.5.7.3.7", "IPSec user");
        extendedUsageOids.put("1.3.6.1.5.5.7.3.8", "Timestamping");
        extendedUsageOids.put("1.3.6.1.4.1.311.20.2.2", "Smartcard Logon");
        extendedUsageOids.put("1.3.6.1.5.5.7.3.9", "OCSP signer");

        userInfos = CacheBuilder.newBuilder()
                .maximumSize(1000)
                .expireAfterAccess(1, TimeUnit.HOURS)
                .build(
                        new CacheLoader<String, UserInfo>() {
                            public UserInfo load(String key) throws CertificateException, IOException {
                                return getUserInfoFromHeader(key);
                            }
                        }
                );
    }

    private static UserInfo getUserInfoFromHeader(String header) throws IOException, CertificateException {
        final String normalizedHeader = normalizePEM(header);
        log.debug("Header: {}", normalizedHeader);

        try (PEMParser certReader = new PEMParser(new StringReader(normalizedHeader))) {
            // Parse the certificate from header
            Object certObj = certReader.readObject();

            if (!(certObj instanceof X509CertificateHolder)) {
                throw new CertificateException("Unable to parse trusted header");
            }

            X509CertificateHolder certificate = (X509CertificateHolder) certObj;

            // Inspect the certificate
            Map<String, String> certificateInformation = convertCertificateInformation(certificate);

            // Debug logging to assist in diagnostics
            for (Map.Entry<String, String> entry : certificateInformation.entrySet()) {
                log.debug("Parsed certificate information {} : {}", entry.getKey(), entry.getValue());
            }

            // Handle VRK CA for Qualified Certificates - G2
            // ... and everything that had compatible attributes, at least until more needs arise
            //if ("C=FI,O=Vaestorekisterikeskus CA,OU=Organisaatiovarmenteet,CN=VRK CA for Qualified Certificates - G2".equals(certificateInformation.getOrDefault("ISSUER", "unknown"))) {
                return new UserInfo(
                        certificateInformation.getOrDefault("rfc822Name", "unknown@unknown"),
                        certificateInformation.getOrDefault("rfc822Name", "unknown@unknown"),
                        certificateInformation.getOrDefault("GIVENNAME", "unknown") + " " +
                                certificateInformation.getOrDefault("SURNAME", "unknown")
                );
            //}

            // Probably no handler available for this certificate
            //log.warn("No handler for certificate issued by {}", certificateInformation.getOrDefault("ISSUER", "unknown"));
        }

        //return null;
    }

    private static Map<String, String> convertCertificateInformation(X509CertificateHolder certificate) throws CertificateException {
        final X500NameStyle x500NameStyle = BCStyle.INSTANCE;
        final CertificateInfo<String, String> certInfo = new CertificateInfo<>();

        // Stores relative distinguished names of Subject
        X500Name subject = certificate.getSubject();
        for (RDN rdn : subject.getRDNs()) {
            if (rdn.getFirst() == null) {
                log.warn("Unable to get first RDN");
                continue;
            }
            AttributeTypeAndValue atav = rdn.getFirst();
            if (atav == null) {
                log.warn("Unable to get first AttributeTypeAndValue");
                continue;
            }
            String displayName = x500NameStyle.oidToDisplayName(atav.getType());
            ASN1Encodable value = atav.getValue();
            if (displayName != null && value != null) {
                certInfo.putLogString(displayName, value);
            }
        }

        certInfo.putLogString("CERT_SERIAL", certificate.getSerialNumber());
        certInfo.putLogString("ISSUER", certificate.getIssuer());

        // Convert to java.security.cert.X509Certificate
        X509Certificate jcert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificate);

        // Set subject alternate names
        // There may be several of the same type in the certificate. This implementation will overwrite in collisions!
        Collection<List<?>> sans = jcert.getSubjectAlternativeNames();
        if (sans != null)
            for (List<?> san : sans) {
                Object[] sanArray = san.toArray();
                switch ((Integer) sanArray[0]) {
                    // These are known to be Strings
                    case 1:
                        if (sanArray[1] != null) certInfo.putLogString("rfc822Name", sanArray[1]);
                        break;
                    case 2:
                        if (sanArray[1] != null) certInfo.putLogString("dNSName", sanArray[1]);
                        break;
                    case 4:
                        if (sanArray[1] != null) certInfo.putLogString("directoryName", sanArray[1]);
                        break;
                    case 6:
                        if (sanArray[1] != null) certInfo.putLogString("uniformResourceIdentifier", sanArray[1]);
                        break;
                    case 7:
                        if (sanArray[1] != null) certInfo.putLogString("iPAddress", sanArray[1]);
                        break;
                    case 8:
                        if (sanArray[1] != null) certInfo.putLogString("registeredID", sanArray[1]);
                        break;
                }
            }

        // Populate key usages
        boolean[] keyUsages = jcert.getKeyUsage();
        if (keyUsages != null && keyUsages.length == 9) {
            if (keyUsages[0]) certInfo.putLogString("Usage digitalSignature", "true");
            if (keyUsages[1]) certInfo.putLogString("Usage nonRepudiation", "true");
            if (keyUsages[2]) certInfo.putLogString("Usage keyEncipherment", "true");
            if (keyUsages[3]) certInfo.putLogString("Usage dataEncipherment", "true");
            if (keyUsages[4]) certInfo.putLogString("Usage keyAgreement", "true");
            if (keyUsages[5]) certInfo.putLogString("Usage keyCertSign", "true");
            if (keyUsages[6]) certInfo.putLogString("Usage cRLSign", "true");
            if (keyUsages[7]) certInfo.putLogString("Usage encipherOnly", "true");
            if (keyUsages[8]) certInfo.putLogString("Usage decipherOnly", "true");
        }

        // Populate extended usages
        List<String> extendedUsage = jcert.getExtendedKeyUsage();
        if (extendedUsage != null)
            for (String s : extendedUsage) {
                if (extendedUsageOids.containsKey(s)) {
                    certInfo.putLogString("Usage " + extendedUsageOids.get(s), "true");
                } else {
                    log.warn("Unknown extended usage OID: {}", s);
                }
            }

        return certInfo;
    }

    public static UserInfo getUserinfoFromHeader(String header) {
        try {
            return userInfos.get(header);
        } catch (ExecutionException e) {
            log.error("Unable to get user information from cache", e);
        }
        return null;
    }

    private static final String PEM_MAIN_REGEX = "^---[-]+BEGIN[^-]+---[-]+([^-]*)--[-]+END [^-]+---[-]+$";
    private static final Pattern pemMainRegex = Pattern.compile(PEM_MAIN_REGEX);

    public static String normalizePEM(String header) {
        final Matcher matcher = pemMainRegex.matcher(header);
        if (matcher.matches()) {
            return "-----BEGIN CERTIFICATE-----\n" +
                    matcher.group(1).trim().replace(" ","\n") +
                    "\n-----END CERTIFICATE-----\n";
        }
        // Unable to clean this mess up
        return header;
    }

}
