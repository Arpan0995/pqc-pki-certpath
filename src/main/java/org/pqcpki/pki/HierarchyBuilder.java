package org.pqcpki.pki;

import org.pqcpki.algo.AlgorithmSpec;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds a multi-tier X.509 hierarchy for one algorithm: a self-signed root CA, zero or more
 * intermediate CAs, and an end-entity leaf, each certificate signed by the tier above it (design §5).
 *
 * <p>Every certificate carries the same profile ({@link CertificateProfile}) and the same two
 * validation-relevant extensions — BasicConstraints and KeyUsage, via {@link CertificateIssuer} — so
 * that only the signature algorithm varies between hierarchies. Keys are generated from the seed via
 * {@link KeyPairs}, one draw per tier, so a hierarchy is reproducible from (algorithm, seed, tier count).
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
            certs.add(CertificateIssuer.issue(
                    spec.signatureAlgorithm(),
                    name(tiers, isRoot ? tier : tier - 1),
                    name(tiers, tier),
                    BigInteger.valueOf(tier + 1L),
                    subject.getPublic(),
                    issuer.getPrivate(),
                    profile,
                    isLeaf ? CertificateIssuer.Options.leafCert() : CertificateIssuer.Options.caCert()));
        }
        return new Hierarchy(spec, certs);
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
}
