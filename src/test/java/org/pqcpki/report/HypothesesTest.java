package org.pqcpki.report;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pqcpki.algo.Algorithms;
import org.pqcpki.measure.CertificateSize;
import org.pqcpki.measure.Stats;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests the mechanical hypothesis scoring on synthetic results with numbers we control, so the verdict
 * logic is checked independently of any real measurement. If these rules were wrong, a real run could
 * report a hypothesis as supported when the numbers say otherwise.
 */
class HypothesesTest {

    /** Build a result whose every certificate has the given size, so transmitted = (tiers−1)·total. */
    private static HierarchyResult result(String id, int tiers, int certTotal, int keyBytes,
                                          int sigBytes, Double medianMicros) {
        List<CertificateSize> sizes = new ArrayList<>();
        for (int i = 0; i < tiers; i++) {
            sizes.add(new CertificateSize(certTotal, certTotal - sigBytes, keyBytes, sigBytes));
        }
        Stats timing = medianMicros == null ? null : Stats.of(new double[]{medianMicros});
        return new HierarchyResult(Algorithms.byId(id), tiers, sizes, timing, "SUN");
    }

    /** A realistic-shaped dataset: classical small and slow-ish; ML-DSA large but fast; SLH-DSA huge. */
    private static List<HierarchyResult> realisticShape() {
        List<HierarchyResult> r = new ArrayList<>();
        for (int t : new int[]{2, 3, 4}) {
            r.add(result("ecdsa-p256", t, 330, 91, 72, 600.0));
            r.add(result("ml-dsa-65", t, 5450, 1974, 3309, 250.0));            // faster than classical
            r.add(result("slh-dsa-sha2-128f", t, 17300, 50, 17088, 3000.0));   // 'f': huge, 5× time
            r.add(result("mldsa65-ecdsa-p384", t, 5650, 2070, 3413, 500.0));   // composite ≈ ML-DSA
        }
        return r;
    }

    private static Map<String, Hypothesis> byId(List<HierarchyResult> results) {
        return Hypotheses.evaluate(results).stream()
                .collect(Collectors.toMap(Hypothesis::id, h -> h));
    }

    @Test
    @DisplayName("all four hypotheses hold on a realistically-shaped dataset")
    void allSupportedOnRealisticShape() {
        Map<String, Hypothesis> h = byId(realisticShape());
        assertTrue(h.get("H1").supported(), h.get("H1").evidence());
        assertTrue(h.get("H2").supported(), h.get("H2").evidence());
        assertTrue(h.get("H3").supported(), h.get("H3").evidence());
        assertTrue(h.get("H4").supported(), h.get("H4").evidence());
    }

    @Test
    @DisplayName("H1 fails if a fast SLH-DSA certificate does not exceed a TLS record")
    void h1FailsWhenFastCertFits() {
        List<HierarchyResult> r = new ArrayList<>();
        r.add(result("ecdsa-p256", 3, 330, 91, 72, 600.0));
        r.add(result("ml-dsa-65", 3, 5450, 1974, 3309, 250.0));
        // A 'f' variant made artificially small: 8 KB cert does not cross the 16 KB record.
        r.add(result("slh-dsa-sha2-128f", 3, 8000, 50, 7800, 3000.0));
        assertFalse(byId(r).get("H1").supported());
    }

    @Test
    @DisplayName("H2 fails if validation time blows up as much as size does")
    void h2FailsWhenCpuTracksBytes() {
        // ML-DSA made pathologically slow so the CPU penalty matches the size penalty — the
        // "bytes not CPU" claim should then not hold.
        List<HierarchyResult> r = new ArrayList<>();
        r.add(result("ecdsa-p256", 3, 330, 91, 72, 100.0));
        r.add(result("ml-dsa-65", 3, 5450, 1974, 3309, 6000.0));  // 60× classical time
        r.add(result("slh-dsa-sha2-128f", 3, 17300, 50, 17088, 6000.0));
        Hypothesis h2 = byId(r).get("H2");
        assertFalse(h2.supported(), h2.evidence());
    }

    @Test
    @DisplayName("H3 fails if a composite chain nearly doubles its ML-DSA counterpart")
    void h3FailsWhenCompositeDoubles() {
        List<HierarchyResult> r = new ArrayList<>(realisticShape());
        // Replace the composite 3-tier with one twice the size of ML-DSA-65.
        r.removeIf(x -> x.algorithm().id().equals("mldsa65-ecdsa-p384") && x.tiers() == 3);
        r.add(result("mldsa65-ecdsa-p384", 3, 10900, 2070, 3413, 500.0));
        assertFalse(byId(r).get("H3").supported());
    }

    @Test
    @DisplayName("a PQC-only subset with no classical baseline degrades instead of crashing")
    void degradesWithoutBaseline() {
        // A user running --algorithms=ml-dsa-65 alone must still get a report, not an exception.
        List<HierarchyResult> pqcOnly = List.of(result("ml-dsa-65", 3, 5450, 1974, 3309, 250.0));
        Map<String, Hypothesis> h = byId(pqcOnly);
        assertFalse(h.get("H1").supported());
        assertTrue(h.get("H1").evidence().contains("not evaluable"), h.get("H1").evidence());
        assertFalse(h.get("H2").supported());
    }

    @Test
    @DisplayName("H4 fails if chain size grows non-linearly with depth")
    void h4FailsWhenNonLinear() {
        List<HierarchyResult> r = new ArrayList<>();
        r.add(result("ecdsa-p256", 3, 330, 91, 72, 600.0));
        // ML-DSA-65 with wildly different per-cert sizes per depth breaks the linear ratio.
        r.add(result("ml-dsa-65", 2, 5000, 1974, 3000, 250.0));
        r.add(result("ml-dsa-65", 3, 5000, 1974, 3000, 250.0));   // 3-tier == 2-tier·2 expected, but…
        r.add(result("ml-dsa-65", 4, 30000, 1974, 3000, 250.0));  // 4-tier far off linear
        assertFalse(byId(r).get("H4").supported());
    }
}
