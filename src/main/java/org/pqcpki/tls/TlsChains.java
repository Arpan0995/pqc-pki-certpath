package org.pqcpki.tls;

import org.pqcpki.algo.AlgorithmSpec;
import org.pqcpki.algo.Algorithms;
import org.pqcpki.pki.CertificateIssuer;
import org.pqcpki.pki.CertificateProfile;
import org.pqcpki.pki.KeyPairs;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Builds the server-side certificate chains the two TLS experiments need (design §13). A chain here is
 * what a server would actually present: the leaf and any intermediates, plus the private key to
 * authenticate with and the root the client is asked to trust.
 */
public final class TlsChains {

    private static final CertificateProfile PROFILE = CertificateProfile.standard();
    private static final String LEAF_DNS = "localhost";

    private TlsChains() {
    }

    /** A server chain, ready to hand to {@link LoopbackHandshake}. */
    public record ServerChain(List<X509Certificate> chain, PrivateKey leafKey,
                              X509Certificate trustAnchor) {

        /** The bytes the server transmits (the whole chain; the root is the separate trust anchor). */
        public int transmittedBytes() {
            try {
                int sum = 0;
                for (X509Certificate certificate : chain) {
                    sum += certificate.getEncoded().length;
                }
                return sum;
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    /**
     * A two-tier chain signed with {@code spec}: a root CA and a server leaf, the leaf sent and the root
     * trusted. Used by the authentication experiment, where the question is only whether JSSE can
     * negotiate the leaf's signature scheme — so size is kept minimal.
     */
    public static ServerChain authChain(AlgorithmSpec spec, long seed) {
        KeyPair root = KeyPairs.generate(spec, seed);
        KeyPair leaf = KeyPairs.generate(spec, seed + 1);
        X509Certificate rootCert = CertificateIssuer.issue(spec.signatureAlgorithm(),
                "CN=TLS Test Root", "CN=TLS Test Root", BigInteger.ONE,
                root.getPublic(), root.getPrivate(), PROFILE, CertificateIssuer.Options.caCert());
        X509Certificate leafCert = CertificateIssuer.issue(spec.signatureAlgorithm(),
                "CN=TLS Test Root", "CN=" + LEAF_DNS, BigInteger.TWO,
                leaf.getPublic(), root.getPrivate(), PROFILE,
                CertificateIssuer.Options.serverLeafCert(LEAF_DNS));
        return new ServerChain(List.of(leafCert), leaf.getPrivate(), rootCert);
    }

    /**
     * A three-tier ECDSA chain (root → intermediate → server leaf) whose transmitted portion
     * (leaf + intermediate) is padded to approximately {@code targetBytes}. Used by the size experiment:
     * ECDSA authenticates fine on both JSSE providers, so any failure here is attributable to size
     * alone. The target is a real post-quantum chain's measured size, which is why a classical chain is
     * grown to match it — real PQC certificates cannot be authenticated by JSSE yet, so the size axis
     * must be isolated with certificates JSSE accepts.
     */
    public static ServerChain sizedEcChain(int targetBytes, long seed) {
        AlgorithmSpec ec = Algorithms.byId("ecdsa-p256");
        // Two transmitted certs share the padding; subtract a rough base so the total lands near target.
        int padPerCert = Math.max(0, (targetBytes - 800) / 2);

        KeyPair root = KeyPairs.generate(ec, seed);
        KeyPair intermediate = KeyPairs.generate(ec, seed + 1);
        KeyPair leaf = KeyPairs.generate(ec, seed + 2);

        X509Certificate rootCert = CertificateIssuer.issue(ec.signatureAlgorithm(),
                "CN=Size Test Root", "CN=Size Test Root", BigInteger.ONE,
                root.getPublic(), root.getPrivate(), PROFILE, CertificateIssuer.Options.caCert());
        X509Certificate interCert = CertificateIssuer.issue(ec.signatureAlgorithm(),
                "CN=Size Test Root", "CN=Size Test Intermediate", BigInteger.TWO,
                intermediate.getPublic(), root.getPrivate(), PROFILE,
                CertificateIssuer.Options.caCert().withPadding(padPerCert));
        X509Certificate leafCert = CertificateIssuer.issue(ec.signatureAlgorithm(),
                "CN=Size Test Intermediate", "CN=" + LEAF_DNS, BigInteger.valueOf(3),
                leaf.getPublic(), intermediate.getPrivate(), PROFILE,
                CertificateIssuer.Options.serverLeafCert(LEAF_DNS).withPadding(padPerCert));
        return new ServerChain(List.of(leafCert, interCert), leaf.getPrivate(), rootCert);
    }
}
