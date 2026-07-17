package org.pqcpki.measure;

import org.bouncycastle.cert.X509CertificateHolder;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * The DER-encoded size of one certificate, decomposed into the parts that answer RQ3: how the cost is
 * split between the public key and the signature.
 *
 * <p>An X.509 {@code Certificate} is {@code SEQUENCE { tbsCertificate, signatureAlgorithm,
 * signatureValue }}. The {@code tbsCertificate} contains the SubjectPublicKeyInfo (the public key). So
 * three numbers tell the story: the whole certificate, the raw signature bytes, and the encoded public
 * key. The remainder — names, validity, extensions, ASN.1 framing — is the fixed X.509 scaffolding, the
 * same for every algorithm.
 *
 * @param totalBytes         the full DER-encoded certificate
 * @param tbsBytes           the to-be-signed portion (everything the signature covers)
 * @param publicKeyBytes     the encoded SubjectPublicKeyInfo
 * @param signatureBytes     the raw signature value (the BIT STRING contents, not its ASN.1 wrapper)
 */
public record CertificateSize(int totalBytes, int tbsBytes, int publicKeyBytes, int signatureBytes) {

    /** Decompose a certificate by re-reading its ASN.1 structure. */
    public static CertificateSize of(X509Certificate certificate) {
        try {
            byte[] encoded = certificate.getEncoded();
            org.bouncycastle.asn1.x509.Certificate asn1 =
                    new X509CertificateHolder(encoded).toASN1Structure();
            int total = encoded.length;
            int tbs = asn1.getTBSCertificate().getEncoded().length;
            int publicKey = asn1.getSubjectPublicKeyInfo().getEncoded().length;
            int signature = asn1.getSignature().getBytes().length;
            return new CertificateSize(total, tbs, publicKey, signature);
        } catch (CertificateEncodingException | IOException e) {
            throw new IllegalStateException("could not decode a certificate for size measurement", e);
        }
    }

    /**
     * The bytes that are neither public key nor signature: distinguished names, validity, serial,
     * extensions, and ASN.1 framing. Constant across algorithms for a fixed profile, so it isolates the
     * cryptographic cost from the X.509 overhead.
     */
    public int overheadBytes() {
        return totalBytes - publicKeyBytes - signatureBytes;
    }
}
