package org.pqcpki.pki;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.Random;

/**
 * Issues a single X.509 certificate. The one place any certificate is minted, so the hierarchy builder,
 * the cross-certification model, and the TLS harness all produce certificates with identical structure —
 * only the parameters vary.
 *
 * <p>Kept low-level on purpose: it takes an explicit issuer and subject rather than assuming a
 * parent/child relationship, because a cross-certificate is exactly the case where the issuer is not the
 * subject's parent in any tree — one CA vouching for another CA's key under its own name.
 */
public final class CertificateIssuer {

    /** OID under a private-enterprise arc, used only to carry padding bytes in the size experiments. */
    private static final ASN1ObjectIdentifier PADDING_OID =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1");

    private CertificateIssuer() {
    }

    /**
     * What kind of certificate to issue, beyond the issuer/subject/key identity.
     *
     * @param ca            whether this is a CA certificate (BasicConstraints cA, KeyUsage keyCertSign)
     * @param serverAuthDns if non-null, add EKU serverAuth and a dNSName SAN — makes it a usable TLS
     *                      server leaf
     * @param paddingBytes  if positive, add a non-critical extension of this many random bytes; used to
     *                      grow a certificate to a target size in the TLS size-limit experiments, since
     *                      real PQC certificates cannot be authenticated by JSSE yet
     */
    public record Options(boolean ca, String serverAuthDns, int paddingBytes) {

        public static Options caCert() {
            return new Options(true, null, 0);
        }

        public static Options leafCert() {
            return new Options(false, null, 0);
        }

        public static Options serverLeafCert(String dnsName) {
            return new Options(false, dnsName, 0);
        }

        public Options withPadding(int bytes) {
            return new Options(ca, serverAuthDns, bytes);
        }
    }

    /**
     * Issue a certificate.
     *
     * @param signatureAlgorithm JCA signature name (e.g. {@code ML-DSA-65}, {@code SHA256withECDSA})
     * @param issuerDn           the issuing CA's distinguished name (equals subjectDn for a self-signed root)
     * @param subjectDn          the subject's distinguished name
     * @param serial             certificate serial number
     * @param subjectKey         the subject's public key (for a cross-certificate, the existing CA's key)
     * @param issuerKey          the issuer's private key, which signs
     * @param profile            validity window
     * @param options            certificate kind
     */
    public static X509Certificate issue(String signatureAlgorithm, String issuerDn, String subjectDn,
                                        BigInteger serial, PublicKey subjectKey, PrivateKey issuerKey,
                                        CertificateProfile profile, Options options) {
        try {
            Instant now = Instant.now();
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    new X500Name(issuerDn), serial,
                    Date.from(now.minus(profile.notBeforeSkew())),
                    Date.from(now.plus(profile.validity())),
                    new X500Name(subjectDn), subjectKey);

            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(options.ca()));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(options.ca()
                    ? KeyUsage.keyCertSign | KeyUsage.cRLSign
                    : KeyUsage.digitalSignature));
            if (options.serverAuthDns() != null) {
                builder.addExtension(Extension.extendedKeyUsage, false,
                        new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
                builder.addExtension(Extension.subjectAlternativeName, false,
                        new GeneralNames(new GeneralName(GeneralName.dNSName, options.serverAuthDns())));
            }
            if (options.paddingBytes() > 0) {
                byte[] padding = new byte[options.paddingBytes()];
                // Deterministic filler; content is irrelevant, only the encoded length matters.
                new Random(serial.longValue()).nextBytes(padding);
                builder.addExtension(PADDING_OID, false, new DEROctetString(padding));
            }

            ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm)
                    .setProvider(KeyPairs.PROVIDER).build(issuerKey);
            X509CertificateHolder holder = builder.build(signer);
            return new JcaX509CertificateConverter().setProvider(KeyPairs.PROVIDER).getCertificate(holder);
        } catch (OperatorCreationException | CertificateException | CertIOException e) {
            throw new IllegalStateException(
                    "failed to issue certificate " + subjectDn + " (sig " + signatureAlgorithm + ")", e);
        }
    }
}
