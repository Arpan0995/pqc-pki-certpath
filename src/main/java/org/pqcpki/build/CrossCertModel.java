package org.pqcpki.build;

import org.pqcpki.algo.AlgorithmSpec;
import org.pqcpki.pki.CertificateIssuer;
import org.pqcpki.pki.CertificateProfile;
import org.pqcpki.pki.KeyPairs;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds the cross-certified topologies the path-building experiments run over (design §14), modelled on
 * how Federal PKI is actually structured: a bridge that many partners cross-certify, so a single CA name
 * carries several issuer certificates.
 *
 * <p>Two scenario shapes:
 *
 * <ul>
 *   <li>{@link #branching} — a controlled stress test. One bridged CA name is issued a certificate by
 *       {@code k} different roots, only one of which (the trust anchor) leads anywhere. Sweeping {@code k}
 *       measures how path discovery scales with the number of candidate issuers a name has, and whether
 *       the post-quantum signature cost amplifies it.
 *   <li>{@link #federalBridge} — a realistic depth-five path through a Federal-Bridge-shaped hierarchy
 *       with decoy cross-certificates, reporting the concrete migration cost of a government-style
 *       deployment.
 * </ul>
 */
public final class CrossCertModel {

    private static final CertificateProfile PROFILE = CertificateProfile.standard();
    private final long seed;

    public CrossCertModel(long seed) {
        this.seed = seed;
    }

    /** Default depth of each decoy (and real) branch when only the branching factor is being swept. */
    public static final int DEFAULT_DECOY_DEPTH = 3;

    /** Convenience: a branching scenario with decoy branches of the default depth. */
    public CrossCertScenario branching(AlgorithmSpec spec, int candidateIssuers) {
        return branching(spec, candidateIssuers, DEFAULT_DECOY_DEPTH);
    }

    /**
     * A bridged CA name with {@code candidateIssuers} cross-certificates — one that ultimately reaches
     * the trust anchor, the rest leading to untrusted decoy roots. Crucially, every branch is
     * {@code decoyDepth} intermediates deep, so a decoy is not a one-hop dead end the builder can
     * dismiss immediately: to reject it, the builder must walk the whole branch down to its untrusted
     * root and back.
     *
     * <p>This is the strengthened branching test. If discovery time still does not grow with the number
     * of such multi-hop candidates, the conclusion is strong: the JDK builder is not exploring — and
     * therefore not verifying — the dead-end branches at all, so cross-certificate breadth is free
     * regardless of the signature algorithm. If instead it grows (and grows faster for a slow verifier),
     * the builder is paying to explore branches it discards.
     *
     * @param candidateIssuers how many issuer certificates the bridged name carries (branching factor)
     * @param decoyDepth       intermediates between the bridged name and each branch's root
     */
    public CrossCertScenario branching(AlgorithmSpec spec, int candidateIssuers, int decoyDepth) {
        if (candidateIssuers < 1) {
            throw new IllegalArgumentException("need at least one candidate issuer");
        }
        if (decoyDepth < 1) {
            throw new IllegalArgumentException("decoy depth must be at least 1");
        }
        String sig = spec.signatureAlgorithm();
        long[] s = {seed};

        KeyPair anchorKey = KeyPairs.generate(spec, s[0]++);
        X509Certificate anchor = selfSigned(sig, "CN=Trusted Bridge", anchorKey, s[0]++);

        KeyPair bridgedKey = KeyPairs.generate(spec, s[0]++);
        String bridgedDn = "CN=Bridged Agency CA";
        List<X509Certificate> pool = new ArrayList<>();

        // (k-1) decoy branches, each depth intermediates deep, ending at an untrusted self-signed root.
        for (int i = 1; i < candidateIssuers; i++) {
            KeyPair decoyRoot = KeyPairs.generate(spec, s[0]++);
            pool.add(selfSigned(sig, "CN=Decoy " + i + " Root", decoyRoot, s[0]++));
            KeyPair bottom = chainDown(spec, sig, pool, "Decoy " + i, decoyDepth,
                    "CN=Decoy " + i + " Root", decoyRoot, s);
            // The bridged name, cross-certified by this decoy branch's bottom intermediate.
            pool.add(CertificateIssuer.issue(sig, "CN=Decoy " + i + " CA " + decoyDepth, bridgedDn,
                    BigInteger.valueOf(s[0]++), bridgedKey.getPublic(), bottom.getPrivate(), PROFILE,
                    CertificateIssuer.Options.caCert()));
        }

        // The real branch: depth intermediates from the anchor down to the bridged name. Added last.
        KeyPair realBottom = chainDown(spec, sig, pool, "Real", decoyDepth,
                "CN=Trusted Bridge", anchorKey, s);
        pool.add(CertificateIssuer.issue(sig, "CN=Real CA " + decoyDepth, bridgedDn,
                BigInteger.valueOf(s[0]++), bridgedKey.getPublic(), realBottom.getPrivate(), PROFILE,
                CertificateIssuer.Options.caCert()));

        KeyPair leafKey = KeyPairs.generate(spec, s[0]++);
        X509Certificate leaf = CertificateIssuer.issue(sig, bridgedDn, "CN=leaf.agency.test",
                BigInteger.valueOf(s[0]++), leafKey.getPublic(), bridgedKey.getPrivate(), PROFILE,
                CertificateIssuer.Options.leafCert());
        pool.add(leaf);

        return new CrossCertScenario(
                "branching-k" + candidateIssuers + "-d" + decoyDepth, spec, anchor, leaf, pool,
                candidateIssuers);
    }

    /**
     * Build a linear chain of {@code depth} CA certificates descending from {@code topIssuerDn} (signed
     * by {@code topKey}), naming them {@code CN=<label> CA 1 .. <label> CA depth}, adding each to the
     * pool, and returning the bottom key so the caller can issue the next certificate under it.
     */
    private KeyPair chainDown(AlgorithmSpec spec, String sig, List<X509Certificate> pool, String label,
                              int depth, String topIssuerDn, KeyPair topKey, long[] s) {
        KeyPair issuerKey = topKey;
        String issuerDn = topIssuerDn;
        KeyPair subjectKey = null;
        for (int level = 1; level <= depth; level++) {
            subjectKey = KeyPairs.generate(spec, s[0]++);
            String subjectDn = "CN=" + label + " CA " + level;
            pool.add(CertificateIssuer.issue(sig, issuerDn, subjectDn, BigInteger.valueOf(s[0]++),
                    subjectKey.getPublic(), issuerKey.getPrivate(), PROFILE,
                    CertificateIssuer.Options.caCert()));
            issuerKey = subjectKey;
            issuerDn = subjectDn;
        }
        return subjectKey;
    }

    /**
     * A Federal-Bridge-shaped hierarchy: a Common Policy Root (the anchor) cross-certifies a Federal
     * Bridge CA, which anchors an agency CA, an agency sub-CA, and the leaf — a depth-five path. The
     * bridge's name also carries decoy cross-certificates from partner bridges, so discovery is real.
     */
    public CrossCertScenario federalBridge(AlgorithmSpec spec, int decoyPartners) {
        String sig = spec.signatureAlgorithm();
        long s = seed;

        KeyPair commonRoot = KeyPairs.generate(spec, s++);
        X509Certificate anchor = selfSigned(sig, "CN=Common Policy Root", commonRoot, s);

        KeyPair bridgeKey = KeyPairs.generate(spec, s++);
        String bridgeDn = "CN=Federal Bridge CA";
        KeyPair agencyKey = KeyPairs.generate(spec, s++);
        String agencyDn = "CN=Agency Principal CA";
        KeyPair subKey = KeyPairs.generate(spec, s++);
        String subDn = "CN=Agency Sub CA";
        KeyPair leafKey = KeyPairs.generate(spec, s++);

        List<X509Certificate> pool = new ArrayList<>();
        // Common Policy Root cross-certifies the Federal Bridge — the link that reaches the anchor.
        pool.add(CertificateIssuer.issue(sig, "CN=Common Policy Root", bridgeDn, BigInteger.valueOf(1L),
                bridgeKey.getPublic(), commonRoot.getPrivate(), PROFILE,
                CertificateIssuer.Options.caCert()));
        // Decoy partner bridges also cross-certify the Federal Bridge name — candidates that go nowhere.
        for (int i = 1; i <= decoyPartners; i++) {
            KeyPair partner = KeyPairs.generate(spec, s++);
            pool.add(CertificateIssuer.issue(sig, "CN=Partner Bridge " + i, bridgeDn,
                    BigInteger.valueOf(2000L + i), bridgeKey.getPublic(), partner.getPrivate(), PROFILE,
                    CertificateIssuer.Options.caCert()));
        }
        // Federal Bridge → Agency CA → Agency Sub CA → leaf.
        pool.add(CertificateIssuer.issue(sig, bridgeDn, agencyDn, BigInteger.valueOf(10L),
                agencyKey.getPublic(), bridgeKey.getPrivate(), PROFILE,
                CertificateIssuer.Options.caCert()));
        pool.add(CertificateIssuer.issue(sig, agencyDn, subDn, BigInteger.valueOf(11L),
                subKey.getPublic(), agencyKey.getPrivate(), PROFILE,
                CertificateIssuer.Options.caCert()));
        X509Certificate leaf = CertificateIssuer.issue(sig, subDn, "CN=leaf.agency.gov",
                BigInteger.valueOf(12L), leafKey.getPublic(), subKey.getPrivate(), PROFILE,
                CertificateIssuer.Options.leafCert());
        pool.add(leaf);

        return new CrossCertScenario(
                "federal-bridge", spec, anchor, leaf, pool, decoyPartners + 1);
    }

    private static X509Certificate selfSigned(String sig, String dn, KeyPair key, long serial) {
        return CertificateIssuer.issue(sig, dn, dn, BigInteger.valueOf(serial),
                key.getPublic(), key.getPrivate(), PROFILE, CertificateIssuer.Options.caCert());
    }
}
