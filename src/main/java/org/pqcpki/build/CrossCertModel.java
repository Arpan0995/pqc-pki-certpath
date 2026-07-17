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

    /**
     * A bridged CA whose name has {@code candidateIssuers} issuer certificates — one from the trust
     * anchor, the rest from untrusted decoy roots. The builder walking up from the leaf finds all of
     * them under the same name and must find the one that chains to the anchor.
     */
    public CrossCertScenario branching(AlgorithmSpec spec, int candidateIssuers) {
        if (candidateIssuers < 1) {
            throw new IllegalArgumentException("need at least one candidate issuer");
        }
        String sig = spec.signatureAlgorithm();
        long s = seed;

        KeyPair anchorKey = KeyPairs.generate(spec, s++);
        X509Certificate anchor = selfSigned(sig, "CN=Trusted Bridge", anchorKey, s);

        // One bridged CA identity (one key, one name), cross-certified by many issuers.
        KeyPair bridgedKey = KeyPairs.generate(spec, s++);
        String bridgedDn = "CN=Bridged Agency CA";

        List<X509Certificate> pool = new ArrayList<>();
        // Decoy roots each issue a cross-cert for the bridged CA — candidates that go nowhere.
        for (int i = 1; i < candidateIssuers; i++) {
            KeyPair decoyRoot = KeyPairs.generate(spec, s++);
            X509Certificate decoyCross = CertificateIssuer.issue(sig,
                    "CN=Decoy Partner Root " + i, bridgedDn, BigInteger.valueOf(1000L + i),
                    bridgedKey.getPublic(), decoyRoot.getPrivate(), PROFILE,
                    CertificateIssuer.Options.caCert());
            pool.add(decoyCross);
        }
        // The one that actually chains: issued by the trusted anchor.
        X509Certificate validCross = CertificateIssuer.issue(sig,
                "CN=Trusted Bridge", bridgedDn, BigInteger.valueOf(1L),
                bridgedKey.getPublic(), anchorKey.getPrivate(), PROFILE,
                CertificateIssuer.Options.caCert());
        pool.add(validCross);

        // The leaf, signed by the bridged CA.
        KeyPair leafKey = KeyPairs.generate(spec, s++);
        X509Certificate leaf = CertificateIssuer.issue(sig,
                bridgedDn, "CN=leaf.agency.test", BigInteger.valueOf(9L),
                leafKey.getPublic(), bridgedKey.getPrivate(), PROFILE,
                CertificateIssuer.Options.leafCert());
        pool.add(leaf);

        return new CrossCertScenario(
                "branching-k" + candidateIssuers, spec, anchor, leaf, pool, candidateIssuers);
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
