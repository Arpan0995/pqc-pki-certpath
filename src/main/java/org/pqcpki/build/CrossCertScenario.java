package org.pqcpki.build;

import org.pqcpki.algo.AlgorithmSpec;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * A path-discovery problem for {@link java.security.cert.CertPathBuilder}: a target leaf, a trust
 * anchor, and a pool of certificates to build a path through — some useful, some decoys.
 *
 * <p>Unlike the validation study, where the chain is handed over in order, here the builder must
 * <em>discover</em> the path. That is the situation cross-certification creates and the one Federal PKI
 * actually lives in: a single CA name can have several issuer certificates (one per cross-certifying
 * partner), so walking up from a leaf the builder finds multiple candidates for the same name and must
 * decide which, if any, chains to a trusted anchor.
 *
 * @param name             human-readable scenario name
 * @param algorithm        the algorithm every certificate is signed with
 * @param trustAnchor      the single trusted root
 * @param targetLeaf       the certificate a path is being built for
 * @param pool             the certificates available to build through (excludes the anchor)
 * @param candidateIssuers how many issuer certificates share the bridged CA's name (the branching factor)
 */
public record CrossCertScenario(
        String name,
        AlgorithmSpec algorithm,
        X509Certificate trustAnchor,
        X509Certificate targetLeaf,
        List<X509Certificate> pool,
        int candidateIssuers) {

    public CrossCertScenario {
        pool = List.copyOf(pool);
    }

    /** Total bytes of the discovered-through pool, a rough measure of the store the builder searches. */
    public int poolBytes() {
        try {
            int sum = 0;
            for (X509Certificate certificate : pool) {
                sum += certificate.getEncoded().length;
            }
            return sum;
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
