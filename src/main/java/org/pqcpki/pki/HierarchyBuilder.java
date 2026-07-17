package org.pqcpki.pki;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.pqcpki.algo.AlgorithmSpec;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Builds a multi-tier X.509 hierarchy for one algorithm: a self-signed root CA, zero or more
 * intermediate CAs, and an end-entity leaf, each certificate signed by the tier above it (design §5).
 *
 * <p>Every certificate carries the same profile ({@link CertificateProfile}) and the same two
 * validation-relevant extensions — BasicConstraints and KeyUsage — so that only the signature algorithm
 * varies between hierarchies. Keys are generated from the seed via {@link KeyPairs}, one draw per tier,
 * so a hierarchy is reproducible from (algorithm, seed, tier count).
 */
public final class HierarchyBuilder {

    private final CertificateProfile profile;
    private final long seed;

    public HierarchyBuilder(CertificateProfile profile, long seed) {
        this.profile = profile;
        this.seed = seed;
    }

    /**
     * Build a hierarchy of {@code tiers} certificates (root … leaf) signed with {@code spec}.
     *
     * @param tiers total certificate count, at least 2 (root + leaf)
     */
    public Hierarchy build(AlgorithmSpec spec, int tiers) {
        if (tiers < 2) {
            throw new IllegalArgumentException("tiers must be at least 2 (root + leaf), got " + tiers);
        }
        try {
            List<KeyPair> keys = new ArrayList<>(tiers);
            for (int tier = 0; tier < tiers; tier++) {
                // Distinct per-tier seed so each certificate has its own key, still fully reproducible.
                keys.add(KeyPairs.generate(spec, seed + tier));
            }

            List<X509Certificate> certs = new ArrayList<>(tiers);
            for (int tier = 0; tier < tiers; tier++) {
                boolean isRoot = tier == 0;
                boolean isLeaf = tier == tiers - 1;
                KeyPair subject = keys.get(tier);
                KeyPair issuer = isRoot ? subject : keys.get(tier - 1);
                certs.add(issue(spec, subject.getPublic(), issuer.getPrivate(),
                        name(tiers, tier), name(tiers, isRoot ? tier : tier - 1),
                        BigInteger.valueOf(tier + 1L), !isLeaf));
            }
            return new Hierarchy(spec, certs);
        } catch (OperatorCreationException | CertificateException | CertIOException e) {
            throw new IllegalStateException(
                    "failed to build a " + tiers + "-tier hierarchy for " + spec.displayName(), e);
        }
    }

    /** A stable, human-readable distinguished name per tier, so issuer/subject links are legible. */
    private static String name(int tiers, int tier) {
        if (tier == 0) {
            return "CN=Root CA";
        }
        if (tier == tiers - 1) {
            return "CN=leaf.example.test";
        }
        return "CN=Intermediate CA " + tier;
    }

    private X509Certificate issue(AlgorithmSpec spec, PublicKey subjectKey, PrivateKey issuerKey,
                                  String subjectDn, String issuerDn, BigInteger serial, boolean ca)
            throws OperatorCreationException, CertificateException, CertIOException {
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(profile.notBeforeSkew()));
        Date notAfter = Date.from(now.plus(profile.validity()));

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(issuerDn), serial, notBefore, notAfter, new X500Name(subjectDn), subjectKey);
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(
                ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));

        ContentSigner signer = new JcaContentSignerBuilder(spec.signatureAlgorithm())
                .setProvider(KeyPairs.PROVIDER).build(issuerKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider(KeyPairs.PROVIDER).getCertificate(holder);
    }
}
