package org.pqcpki.report;

import org.pqcpki.env.Environment;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Renders a benchmark run as the Markdown reported in {@code results/} (design §7): what ran, the chain
 * sizes, where they cross size limits, the size decomposition, the validation timing, how both scale
 * with depth, and how the pre-registered hypotheses fared.
 */
public final class ReportWriter {

    private static final int PRIMARY = Hypotheses.PRIMARY_TIERS;

    private ReportWriter() {
    }

    public static String render(List<HierarchyResult> results, long seed,
                                int warmup, int iterations) {
        StringBuilder out = new StringBuilder();
        out.append("# PQC at the PKI Layer — Chain Sizes and CertPath Validation Cost\n\n");
        appendProvenance(out, seed, warmup, iterations, results);
        appendHeadline(out, results);
        appendChainSizes(out, results);
        appendThresholds(out, results);
        appendDecomposition(out, results);
        appendTiming(out, results);
        appendScaling(out, results);
        appendHypotheses(out, results);
        return out.toString();
    }

    private static void appendProvenance(StringBuilder out, long seed, int warmup, int iterations,
                                         List<HierarchyResult> results) {
        String validator = results.stream().findFirst()
                .map(HierarchyResult::validatorProvider).orElse("?");
        out.append("Generated ").append(Instant.now()).append(" by `Benchmark`.\n\n");
        out.append("| Setting | Value |\n|---|---|\n");
        out.append("| BouncyCastle | ").append(Environment.bouncyCastleVersion()).append(" |\n");
        out.append("| JVM | ").append(Environment.jvm()).append(" |\n");
        out.append("| Host | ").append(Environment.host()).append(" |\n");
        out.append("| PKIX validator | ").append(validator)
                .append(" (JDK), signatures via BouncyCastle |\n");
        out.append("| Key-generation seed | `").append(seed).append("` |\n");
        out.append("| Validation warmup / measured | ").append(warmup).append(" / ")
                .append(iterations).append(" iterations |\n\n");
        out.append("Certificate sizes are deterministic per parameter set and are host-independent. "
                + "Validation times are host- and JIT-specific — reported as median and inter-quartile "
                + "range over the measured iterations, on the host above.\n\n");
    }

    /** Lead with the two claims that matter: the size blow-up and the bytes-not-CPU framing. */
    private static void appendHeadline(StringBuilder out, List<HierarchyResult> results) {
        List<HierarchyResult> tier = byTier(results, PRIMARY);
        Optional<HierarchyResult> classical = tier.stream()
                .filter(r -> r.algorithm().id().equals("ecdsa-p256")).findFirst();
        HierarchyResult biggest = tier.stream()
                .max(Comparator.comparingInt(HierarchyResult::transmittedChainBytes)).orElseThrow();

        out.append("## Headline\n\n");
        if (classical.isPresent()) {
            int base = classical.get().transmittedChainBytes();
            out.append(String.format(Locale.ROOT,
                    "At the primary 3-tier depth, a transmitted certificate chain grows from **%,d bytes**"
                            + " (ECDSA P-256) to **%,d bytes** (%s) — a **%.0f×** increase. ",
                    base, biggest.transmittedChainBytes(), biggest.algorithm().displayName(),
                    (double) biggest.transmittedChainBytes() / base));
        }
        long overRecord = byTier(results, PRIMARY).stream()
                .filter(r -> r.leaf().totalBytes() > 16_384).count();
        out.append(String.format(Locale.ROOT,
                "%d algorithm(s) produce a single certificate larger than one TLS record (16,384 B).\n\n",
                overRecord));
    }

    private static void appendChainSizes(StringBuilder out, List<HierarchyResult> results) {
        out.append("## Chain sizes (3-tier: root → intermediate → leaf)\n\n");
        out.append("Transmitted chain = leaf + intermediate (the root is a trust anchor, never sent).\n\n");
        out.append("| Algorithm | Family | Transmitted chain | × ECDSA P-256 | Full hierarchy |\n");
        out.append("|---|---|---:|---:|---:|\n");
        List<HierarchyResult> tier = byTier(results, PRIMARY);
        int base = baselineChain(tier);
        for (HierarchyResult r : tier) {
            out.append("| ").append(r.algorithm().displayName())
                    .append(" | ").append(r.algorithm().family().category())
                    .append(" | ").append(String.format(Locale.ROOT, "%,d B", r.transmittedChainBytes()))
                    .append(" | ").append(String.format(Locale.ROOT, "%.1f×",
                            (double) r.transmittedChainBytes() / base))
                    .append(" | ").append(String.format(Locale.ROOT, "%,d B", r.totalHierarchyBytes()))
                    .append(" |\n");
        }
        out.append('\n');
    }

    private static void appendThresholds(StringBuilder out, List<HierarchyResult> results) {
        out.append("## Size-threshold crossings (3-tier)\n\n");
        List<Threshold> thresholds = Threshold.reference();
        out.append("| Algorithm | Single cert | Transmitted chain |");
        for (Threshold t : thresholds) {
            out.append(' ').append(t.name()).append(" (").append(t.bytes() / 1024).append("K) |");
        }
        out.append("\n|---|---:|---:|");
        thresholds.forEach(t -> out.append("---|"));
        out.append('\n');
        for (HierarchyResult r : byTier(results, PRIMARY)) {
            out.append("| ").append(r.algorithm().displayName())
                    .append(" | ").append(String.format(Locale.ROOT, "%,d B", r.leaf().totalBytes()))
                    .append(" | ").append(String.format(Locale.ROOT, "%,d B", r.transmittedChainBytes()))
                    .append(" |");
            for (Threshold t : thresholds) {
                out.append(' ').append(t.isCrossedBy(r.transmittedChainBytes()) ? "**crosses**" : "ok")
                        .append(" |");
            }
            out.append('\n');
        }
        out.append('\n');
        for (Threshold t : thresholds) {
            out.append("- **").append(t.name()).append("** (").append(String.format("%,d", t.bytes()))
                    .append(" B): ").append(t.description()).append('\n');
        }
        out.append('\n');
    }

    private static void appendDecomposition(StringBuilder out, List<HierarchyResult> results) {
        out.append("## Certificate size decomposition (single leaf certificate)\n\n");
        out.append("Where the bytes go: public key vs signature vs fixed X.509 overhead. This is what "
                + "separates ML-DSA (large key *and* signature) from SLH-DSA (tiny key, dominant "
                + "signature).\n\n");
        out.append("| Algorithm | Total | Public key | Signature | Overhead | Signature share |\n");
        out.append("|---|---:|---:|---:|---:|---:|\n");
        for (HierarchyResult r : byTier(results, PRIMARY)) {
            var s = r.leaf();
            out.append("| ").append(r.algorithm().displayName())
                    .append(" | ").append(String.format(Locale.ROOT, "%,d B", s.totalBytes()))
                    .append(" | ").append(String.format(Locale.ROOT, "%,d B", s.publicKeyBytes()))
                    .append(" | ").append(String.format(Locale.ROOT, "%,d B", s.signatureBytes()))
                    .append(" | ").append(String.format(Locale.ROOT, "%,d B", s.overheadBytes()))
                    .append(" | ").append(String.format(Locale.ROOT, "%.0f%%",
                            100.0 * s.signatureBytes() / s.totalBytes()))
                    .append(" |\n");
        }
        out.append('\n');
    }

    private static void appendTiming(StringBuilder out, List<HierarchyResult> results) {
        List<HierarchyResult> tier = byTier(results, PRIMARY);
        if (tier.stream().noneMatch(HierarchyResult::hasTiming)) {
            return;
        }
        out.append("## Path-validation timing (3-tier)\n\n");
        out.append("Median per-validation time with the inter-quartile range; the JDK PKIX validator, "
                + "revocation disabled. Host- and JIT-specific.\n\n");
        out.append("| Algorithm | Median | IQR | × ECDSA P-256 |\n|---|---:|---:|---:|\n");
        double base = tier.stream().filter(r -> r.algorithm().id().equals("ecdsa-p256") && r.hasTiming())
                .mapToDouble(r -> r.validationMicros().median()).findFirst().orElse(Double.NaN);
        for (HierarchyResult r : tier) {
            if (!r.hasTiming()) {
                continue;
            }
            var s = r.validationMicros();
            out.append("| ").append(r.algorithm().displayName())
                    .append(" | ").append(us(s.median()))
                    .append(" | ").append(us(s.iqr()))
                    .append(" | ").append(Double.isNaN(base) ? "—"
                            : String.format(Locale.ROOT, "%.2f×", s.median() / base))
                    .append(" |\n");
        }
        out.append('\n');
    }

    private static void appendScaling(StringBuilder out, List<HierarchyResult> results) {
        List<Integer> depths = results.stream().map(HierarchyResult::tiers).distinct().sorted().toList();
        if (depths.size() < 2) {
            return;
        }
        out.append("## Scaling with tier depth\n\n");
        out.append("Transmitted chain size by tier count, per algorithm — a linear rise means each added "
                + "tier adds one certificate of roughly constant size.\n\n");
        out.append("| Algorithm |");
        for (int d : depths) {
            out.append(' ').append(d).append("-tier |");
        }
        out.append("\n|---|");
        depths.forEach(d -> out.append("---:|"));
        out.append('\n');
        for (String id : results.stream().map(r -> r.algorithm().id()).distinct().toList()) {
            Optional<HierarchyResult> any = results.stream()
                    .filter(r -> r.algorithm().id().equals(id)).findFirst();
            if (any.isEmpty()) {
                continue;
            }
            out.append("| ").append(any.get().algorithm().displayName()).append(" |");
            for (int d : depths) {
                Optional<HierarchyResult> cell = results.stream()
                        .filter(r -> r.algorithm().id().equals(id) && r.tiers() == d).findFirst();
                out.append(' ').append(cell.map(r ->
                        String.format(Locale.ROOT, "%,d B", r.transmittedChainBytes())).orElse("—"))
                        .append(" |");
            }
            out.append('\n');
        }
        out.append('\n');
    }

    private static void appendHypotheses(StringBuilder out, List<HierarchyResult> results) {
        out.append("## Pre-registered hypotheses\n\n");
        out.append("Fixed in the design before data collection (§4), scored mechanically from the numbers "
                + "above.\n\n");
        out.append("| | Verdict | Evidence |\n|---|---|---|\n");
        List<Hypothesis> hypotheses = Hypotheses.evaluate(results);
        for (Hypothesis h : hypotheses) {
            out.append("| **").append(h.id()).append("** | ").append(h.verdict())
                    .append(" | ").append(h.evidence()).append(" |\n");
        }
        out.append('\n');
        for (Hypothesis h : hypotheses) {
            out.append("- **").append(h.id()).append("** — ").append(h.statement()).append('\n');
        }
        out.append('\n');
    }

    private static int baselineChain(List<HierarchyResult> tier) {
        return tier.stream().filter(r -> r.algorithm().id().equals("ecdsa-p256"))
                .mapToInt(HierarchyResult::transmittedChainBytes).findFirst()
                .orElseGet(() -> baselineFallback(tier));
    }

    private static int baselineFallback(List<HierarchyResult> tier) {
        return tier.stream().mapToInt(HierarchyResult::transmittedChainBytes).min().orElse(1);
    }

    private static List<HierarchyResult> byTier(List<HierarchyResult> results, int tiers) {
        return results.stream().filter(r -> r.tiers() == tiers).toList();
    }

    private static String us(double micros) {
        if (micros >= 1000) {
            return String.format(Locale.ROOT, "%.2f ms", micros / 1000);
        }
        return String.format(Locale.ROOT, "%.1f µs", micros);
    }
}
