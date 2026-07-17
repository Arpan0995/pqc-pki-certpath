package org.pqcpki.report;

import org.pqcpki.algo.Family;

import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;

/**
 * Scores the campaign against the four pre-registered hypotheses (design §4), mechanically, from the
 * measurements alone. As in the sibling {@code pqc-decode-fuzzing} project, expressing the verdicts as
 * code is the point of pre-registering: a rule written down before the numbers arrive cannot quietly
 * relax to fit them, and the raw ratios are reported as evidence so any reader can check the call.
 *
 * <p>The constants below are the thresholds the predictions are judged against. They are deliberately
 * loose — "an order of magnitude", "a small constant factor" — because the hypotheses are about the
 * shape of the result (size dwarfs CPU; composite ≈ ML-DSA + a little), not about hitting a precise
 * number that would itself be host-specific.
 */
public final class Hypotheses {

    /** The primary tier depth the size/timing hypotheses are evaluated at (root → intermediate → leaf). */
    public static final int PRIMARY_TIERS = 3;

    /** "An order of magnitude": PQC chains must be at least this multiple of the classical baseline. */
    private static final double ORDER_OF_MAGNITUDE = 10.0;

    /** "A small constant factor" for ML-DSA validation time relative to classical. */
    private static final double SMALL_FACTOR = 5.0;

    /** For H2: the relative size blow-up must dwarf the relative time blow-up by at least this much. */
    private static final double BYTES_OVER_CPU_MARGIN = 5.0;

    /** For H3: a composite chain must stay below this multiple of its pure ML-DSA counterpart. */
    private static final double COMPOSITE_CEILING = 1.5;

    private Hypotheses() {
    }

    public static List<Hypothesis> evaluate(List<HierarchyResult> results) {
        return List.of(
                evaluateH1(results),
                evaluateH2(results),
                evaluateH3(results),
                evaluateH4(results));
    }

    /** H1: PQC chains ≥ 1 order over classical; SLH-DSA 'f' certs > TLS record; 'f' 3-tier > handshake cap. */
    private static Hypothesis evaluateH1(List<HierarchyResult> results) {
        String statement = "PQC chains are at least an order of magnitude larger than classical; every "
                + "SLH-DSA 'f' certificate exceeds one TLS record (16,384 B); a 3-tier SLH-DSA 'f' chain "
                + "exceeds the JDK max handshake message (32,768 B).";
        List<HierarchyResult> tier = byTier(results, PRIMARY_TIERS);
        OptionalInt classical = tier.stream().filter(r -> r.algorithm().isClassical())
                .mapToInt(HierarchyResult::transmittedChainBytes).min();
        OptionalInt maxPqc = tier.stream().filter(r -> !r.algorithm().isClassical())
                .mapToInt(HierarchyResult::transmittedChainBytes).max();
        if (classical.isEmpty() || maxPqc.isEmpty()) {
            return notEvaluable("H1", statement,
                    "needs both a classical baseline and a PQC algorithm at " + PRIMARY_TIERS + " tiers");
        }
        int classicalChain = classical.getAsInt();
        int maxPqcChain = maxPqc.getAsInt();
        double orderRatio = (double) maxPqcChain / classicalChain;

        boolean everyFastCertOverRecord = tier.stream()
                .filter(Hypotheses::isFastSlhDsa)
                .allMatch(r -> r.leaf().totalBytes() > 16_384);
        boolean everyFastChainOverHandshake = tier.stream()
                .filter(Hypotheses::isFastSlhDsa)
                .allMatch(r -> r.transmittedChainBytes() > 32_768);

        boolean hasFastSlhDsa = tier.stream().anyMatch(Hypotheses::isFastSlhDsa);
        boolean supported = orderRatio >= ORDER_OF_MAGNITUDE
                && hasFastSlhDsa && everyFastCertOverRecord && everyFastChainOverHandshake;
        String evidence = String.format(
                "largest PQC chain is %.1f× the classical baseline (%d vs %d B); "
                        + "SLH-DSA 'f' cert > 16,384 B: %s; SLH-DSA 'f' 3-tier chain > 32,768 B: %s.",
                orderRatio, maxPqcChain, classicalChain,
                hasFastSlhDsa ? everyFastCertOverRecord : "n/a",
                hasFastSlhDsa ? everyFastChainOverHandshake : "n/a");
        return Hypothesis.of("H1", statement, supported, evidence);
    }

    /** H2: ML-DSA validation is competitive with classical, and size dwarfs CPU as the PQC cost. */
    private static Hypothesis evaluateH2(List<HierarchyResult> results) {
        String statement = "ML-DSA path validation is within a small factor of classical, and the "
                + "relative size penalty of PQC dwarfs its relative validation-time penalty: the "
                + "PKI-layer cost is bytes, not CPU.";
        List<HierarchyResult> tier = byTier(results, PRIMARY_TIERS);
        Optional<HierarchyResult> classical = tier.stream()
                .filter(r -> r.algorithm().isClassical() && r.hasTiming())
                .min((a, b) -> Double.compare(a.validationMicros().median(), b.validationMicros().median()));
        Optional<HierarchyResult> mldsa65 = find(tier, "ml-dsa-65");
        if (classical.isEmpty() || mldsa65.isEmpty() || !mldsa65.get().hasTiming()) {
            return notEvaluable("H2", statement,
                    "needs ML-DSA-65 and a classical baseline with timing at " + PRIMARY_TIERS + " tiers");
        }

        double classicalTime = classical.get().validationMicros().median();
        int classicalSize = classical.get().transmittedChainBytes();
        double mldsaTimeFactor = mldsa65.get().validationMicros().median() / classicalTime;

        double maxTimeFactor = tier.stream().filter(r -> !r.algorithm().isClassical() && r.hasTiming())
                .mapToDouble(r -> r.validationMicros().median() / classicalTime).max().orElse(0);
        double maxSizeFactor = tier.stream().filter(r -> !r.algorithm().isClassical())
                .mapToDouble(r -> (double) r.transmittedChainBytes() / classicalSize).max().orElse(0);

        boolean mldsaCompetitive = mldsaTimeFactor <= SMALL_FACTOR;
        boolean bytesDominateCpu = maxSizeFactor >= BYTES_OVER_CPU_MARGIN * maxTimeFactor;
        boolean supported = mldsaCompetitive && bytesDominateCpu;
        String evidence = String.format(
                "ML-DSA-65 validation is %.1f× classical (threshold ≤ %.0f×); across PQC, the worst "
                        + "size penalty is %.0f× vs the worst time penalty %.1f× — size exceeds CPU by "
                        + "%.1f× (threshold ≥ %.0f×).",
                mldsaTimeFactor, SMALL_FACTOR, maxSizeFactor, maxTimeFactor,
                maxTimeFactor > 0 ? maxSizeFactor / maxTimeFactor : Double.POSITIVE_INFINITY,
                BYTES_OVER_CPU_MARGIN);
        return Hypothesis.of("H2", statement, supported, evidence);
    }

    /** H3: composite chains stay close to their pure ML-DSA counterpart, not double it. */
    private static Hypothesis evaluateH3(List<HierarchyResult> results) {
        String statement = "A composite (PQC + classical) chain costs its ML-DSA component plus a modest "
                + "classical increment — closer to pure ML-DSA than to double it.";
        List<HierarchyResult> tier = byTier(results, PRIMARY_TIERS);
        Optional<HierarchyResult> mldsa65 = find(tier, "ml-dsa-65");
        Optional<HierarchyResult> composite = find(tier, "mldsa65-ecdsa-p384");
        if (mldsa65.isEmpty() || composite.isEmpty()) {
            return Hypothesis.of("H3", statement, false, "ML-DSA-65 / composite pair not present.");
        }
        double ratio = (double) composite.get().transmittedChainBytes()
                / mldsa65.get().transmittedChainBytes();
        boolean supported = ratio > 1.0 && ratio < COMPOSITE_CEILING;
        String evidence = String.format(
                "MLDSA65-ECDSA-P384 chain is %.2f× the pure ML-DSA-65 chain (%d vs %d B); "
                        + "supported when between 1.0× and %.1f×.",
                ratio, composite.get().transmittedChainBytes(), mldsa65.get().transmittedChainBytes(),
                COMPOSITE_CEILING);
        return Hypothesis.of("H3", statement, supported, evidence);
    }

    /** H4: chain size scales linearly with tier depth. */
    private static Hypothesis evaluateH4(List<HierarchyResult> results) {
        String statement = "Total chain size scales linearly with tier depth: each added tier adds one "
                + "more transmitted certificate of roughly constant size.";
        Optional<HierarchyResult> two = find(byTier(results, 2), "ml-dsa-65");
        Optional<HierarchyResult> three = find(byTier(results, 3), "ml-dsa-65");
        Optional<HierarchyResult> four = find(byTier(results, 4), "ml-dsa-65");
        if (two.isEmpty() || three.isEmpty() || four.isEmpty()) {
            return Hypothesis.of("H4", statement, false, "ML-DSA-65 not measured at all of 2/3/4 tiers.");
        }
        // Transmitted certs = tiers − 1, so a linear model predicts 1 : 2 : 3 for depths 2 : 3 : 4.
        int t2 = two.get().transmittedChainBytes();
        int t3 = three.get().transmittedChainBytes();
        int t4 = four.get().transmittedChainBytes();
        double r3 = (double) t3 / t2;
        double r4 = (double) t4 / t2;
        boolean supported = near(r3, 2.0, 0.15) && near(r4, 3.0, 0.15);
        String evidence = String.format(
                "ML-DSA-65 transmitted bytes 2/3/4 tiers = %d/%d/%d; ratios to 2-tier are %.2f and "
                        + "%.2f (linear predicts 2.00 and 3.00, ±0.15).",
                t2, t3, t4, r3, r4);
        return Hypothesis.of("H4", statement, supported, evidence);
    }

    private static boolean isFastSlhDsa(HierarchyResult r) {
        return r.algorithm().family() == Family.SLH_DSA && r.algorithm().displayName().endsWith("F");
    }

    private static List<HierarchyResult> byTier(List<HierarchyResult> results, int tiers) {
        return results.stream().filter(r -> r.tiers() == tiers).toList();
    }

    private static Optional<HierarchyResult> find(List<HierarchyResult> results, String algorithmId) {
        return results.stream().filter(r -> r.algorithm().id().equals(algorithmId)).findFirst();
    }

    private static boolean near(double value, double target, double tolerance) {
        return Math.abs(value - target) <= tolerance;
    }

    /**
     * A verdict for a hypothesis the current algorithm subset cannot test — e.g. a run of PQC only,
     * with no classical baseline to compare against. Reported as unsupported with an explanation rather
     * than crashing the whole report, so a partial run still produces output.
     */
    private static Hypothesis notEvaluable(String id, String statement, String why) {
        return Hypothesis.of(id, statement, false, "not evaluable: " + why + ".");
    }
}
