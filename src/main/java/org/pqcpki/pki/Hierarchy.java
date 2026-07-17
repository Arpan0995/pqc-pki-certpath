package org.pqcpki.pki;

import org.pqcpki.algo.AlgorithmSpec;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * A generated certificate hierarchy: the ordered chain from root to leaf, all signed with one
 * algorithm.
 *
 * <p>The two views a measurement needs are kept distinct. {@link #certificates()} is the whole
 * hierarchy, root first — used for size accounting. {@link #transmittedChain()} is what actually goes on
 * the wire during authentication: the leaf and the intermediates, leaf first, <em>without</em> the root.
 * The root is a trust anchor the verifier already holds, so it is never sent, and counting it in a
 * "chain size" would overstate the transmitted cost. That distinction is the whole point of the size
 * measurement, so it lives in the type rather than in each caller.
 *
 * @param algorithm    the algorithm every certificate in this hierarchy is signed with
 * @param certificates root first, leaf last; length equals the tier count
 */
public record Hierarchy(AlgorithmSpec algorithm, List<X509Certificate> certificates) {

    public Hierarchy {
        if (certificates.size() < 2) {
            throw new IllegalArgumentException(
                    "a hierarchy needs at least a root and a leaf, got " + certificates.size());
        }
        certificates = List.copyOf(certificates);
    }

    /** The number of tiers (certificates) from root to leaf. */
    public int tiers() {
        return certificates.size();
    }

    /** The trust anchor: the self-signed root, which a verifier holds and which is never transmitted. */
    public X509Certificate root() {
        return certificates.get(0);
    }

    /** The end-entity certificate being authenticated. */
    public X509Certificate leaf() {
        return certificates.get(certificates.size() - 1);
    }

    /**
     * What a peer actually transmits: leaf first, then each intermediate toward the root, excluding the
     * root itself. This is the ordering {@code CertificateFactory.generateCertPath} expects and the set
     * whose byte size the study reports as the transmitted chain size.
     */
    public List<X509Certificate> transmittedChain() {
        List<X509Certificate> transmitted = new java.util.ArrayList<>(certificates.size() - 1);
        for (int i = certificates.size() - 1; i >= 1; i--) {
            transmitted.add(certificates.get(i));
        }
        return List.copyOf(transmitted);
    }
}
