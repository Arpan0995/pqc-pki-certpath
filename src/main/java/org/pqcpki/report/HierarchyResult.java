package org.pqcpki.report;

import org.pqcpki.algo.AlgorithmSpec;
import org.pqcpki.measure.CertificateSize;
import org.pqcpki.measure.Stats;

import java.util.List;

/**
 * Everything measured for one (algorithm, tier depth) point: the size of each certificate decomposed,
 * the transmitted chain size, and the path-validation timing (design §7).
 *
 * @param algorithm         the algorithm every certificate was signed with
 * @param tiers             certificate count from root to leaf
 * @param certificateSizes  per-certificate sizes, root first
 * @param validationMicros  per-validation time distribution, or null if timing was skipped
 * @param validatorProvider the provider backing the PKIX validator (the JDK's {@code SUN})
 */
public record HierarchyResult(
        AlgorithmSpec algorithm,
        int tiers,
        List<CertificateSize> certificateSizes,
        Stats validationMicros,
        String validatorProvider) {

    public HierarchyResult {
        certificateSizes = List.copyOf(certificateSizes);
    }

    /**
     * The transmitted chain size: every certificate except the root, which is a trust anchor the
     * verifier already holds and never receives. This is the number the size thresholds are checked
     * against.
     */
    public int transmittedChainBytes() {
        int sum = 0;
        for (int i = 1; i < certificateSizes.size(); i++) {
            sum += certificateSizes.get(i).totalBytes();
        }
        return sum;
    }

    /** The whole hierarchy including the root — the storage cost of holding the full chain. */
    public int totalHierarchyBytes() {
        return certificateSizes.stream().mapToInt(CertificateSize::totalBytes).sum();
    }

    /** The end-entity certificate, whose decomposition represents the per-certificate cost. */
    public CertificateSize leaf() {
        return certificateSizes.get(certificateSizes.size() - 1);
    }

    /** Whether validation timing was collected for this point. */
    public boolean hasTiming() {
        return validationMicros != null;
    }
}
