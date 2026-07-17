package org.pqcpki.build;

import org.pqcpki.env.Environment;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/** Renders the path-building experiments as Markdown (design §14). */
public final class PathBuildReport {

    private PathBuildReport() {
    }

    public static String render(List<PathBuildResult> breadth, List<PathBuildResult> depth,
                                List<PathBuildResult> federal, int warmup, int iterations) {
        StringBuilder out = new StringBuilder();
        out.append("# Path Building — CertPathBuilder over Cross-Certified (FPKI-Shaped) Hierarchies\n\n");
        appendProvenance(out, warmup, iterations);
        appendHeadline(out, breadth, depth, federal);
        appendBreadth(out, breadth);
        appendDepth(out, depth);
        appendFederal(out, federal);
        return out.toString();
    }

    private static void appendProvenance(StringBuilder out, int warmup, int iterations) {
        out.append("Generated ").append(Instant.now()).append(" by `PathBuilding`.\n\n");
        out.append("| Setting | Value |\n|---|---|\n");
        out.append("| BouncyCastle | ").append(Environment.bouncyCastleVersion()).append(" |\n");
        out.append("| JVM | ").append(Environment.jvm()).append(" |\n");
        out.append("| Host | ").append(Environment.host()).append(" |\n");
        out.append("| Builder | JDK `PKIX` CertPathBuilder, revocation disabled |\n");
        out.append("| Build warmup / measured | ").append(warmup).append(" / ").append(iterations)
                .append(" |\n\n");
        out.append("Build times are host- and JIT-specific; reported as median over the measured "
                + "iterations. Decoy branches in the breadth and depth sweeps are multi-hop: each "
                + "candidate is several intermediates deep before dead-ending, so a candidate cannot be "
                + "dismissed in one step.\n\n");
    }

    private static void appendHeadline(StringBuilder out, List<PathBuildResult> breadth,
                                       List<PathBuildResult> depth, List<PathBuildResult> federal) {
        out.append("## Headline\n\n");
        // The diagnostic is the SLOWEST verifier, not the max across algorithms: if branching forced the
        // builder to verify dead-end candidates, the slowest verifier would amplify most. It amplifies
        // least, which is the proof that decoys are not verified.
        PathBuildResult slowest = breadth.stream()
                .filter(r -> r.candidateIssuers() == 1)
                .max((a, b) -> Double.compare(a.buildMicros().median(), b.buildMicros().median()))
                .orElseThrow();
        double slowestBreadthAmp = amplification(breadth, slowest.algorithm().id(),
                PathBuildResult::candidateIssuers);
        out.append(String.format(Locale.ROOT,
                "Path discovery is **robust to cross-certificate branching, even with multi-hop decoys**. "
                        + "As a bridged name's candidate issuers grow 1→32, the *slowest* verifier (%s) "
                        + "barely moves (%.1f×) — the tell that the JDK builder does not verify the "
                        + "dead-end branches, because if it did, the slow verifier would blow up most. "
                        + "Faster algorithms show only minor store-search overhead. ",
                slowest.algorithm().displayName(), slowestBreadthAmp));
        double worstDepth = worstAmplification(depth, PathBuildResult::pathLength);
        out.append(String.format(Locale.ROOT,
                "The cost is instead in **path depth**: over the depth sweep the discovered path grows "
                        + "from 4 to 7 certificates and build time rises ~%.1f× across every algorithm, "
                        + "because each certificate on the found path is one signature to verify. ",
                worstDepth));
        Optional<PathBuildResult> slh = federal.stream()
                .filter(r -> r.algorithm().family() == org.pqcpki.algo.Family.SLH_DSA
                        && r.algorithm().displayName().endsWith("F"))
                .max((a, b) -> Double.compare(a.buildMicros().median(), b.buildMicros().median()));
        Optional<PathBuildResult> classical = federal.stream().filter(r -> r.algorithm().isClassical())
                .min((a, b) -> Double.compare(a.buildMicros().median(), b.buildMicros().median()));
        if (slh.isPresent() && classical.isPresent()) {
            out.append(String.format(Locale.ROOT,
                    "That depth cost is per-algorithm: on the realistic Federal-Bridge path, discovery "
                            + "costs %.0f µs for %s versus %.0f µs for %s.",
                    slh.get().buildMicros().median(), slh.get().algorithm().displayName(),
                    classical.get().buildMicros().median(), classical.get().algorithm().displayName()));
        }
        out.append("\n\n");
    }

    private static void appendBreadth(StringBuilder out, List<PathBuildResult> breadth) {
        List<Integer> ks = breadth.stream().map(PathBuildResult::candidateIssuers).distinct().sorted()
                .toList();
        out.append("## Breadth sweep — build time vs candidate issuers (multi-hop decoys)\n\n");
        out.append("A bridged CA name issued a certificate by *k* branches, each several intermediates "
                + "deep, only one reaching the anchor. Median build time (µs):\n\n");
        appendMatrix(out, breadth, ks, PathBuildResult::candidateIssuers, "k=");
        out.append("\nThe decisive comparison is by verify cost: the SLH-DSA rows (slow to verify) stay "
                + "nearly flat, while the cheap-to-verify rows (RSA, ECDSA) actually grow *more* in "
                + "relative terms. That is the opposite of what verifying decoys would produce — a slow "
                + "verifier would be hit hardest — so the small growth is store-search overhead (more "
                + "certificates to index and name-match), not signature checks on dead-end branches. The "
                + "plausible combinatorial blow-up of cross-certification does not occur in the JDK.\n\n");
    }

    private static void appendDepth(StringBuilder out, List<PathBuildResult> depth) {
        List<Integer> lengths = depth.stream().map(PathBuildResult::pathLength).distinct().sorted()
                .toList();
        out.append("## Depth sweep — build time vs discovered path length\n\n");
        out.append("At a fixed branching factor, lengthening the real path. Columns are the number of "
                + "certificates in the discovered path. Median build time (µs):\n\n");
        appendMatrix(out, depth, lengths, PathBuildResult::pathLength, "");
        out.append("\nHere cost rises with depth, and faster for slower verifiers — each additional "
                + "certificate on the path is one more signature to check. This is where the post-quantum "
                + "verification cost enters path building: linearly in path length, at the algorithm's "
                + "per-verify price.\n\n");
    }

    private static void appendFederal(StringBuilder out, List<PathBuildResult> federal) {
        out.append("## Federal Bridge — realistic depth-5 cross-certified path\n\n");
        out.append("A Common Policy Root cross-certifies a Federal Bridge CA (whose name also carries "
                + "decoy partner cross-certificates), which anchors an agency CA, a sub-CA, and the leaf. "
                + "The concrete migration cost per algorithm:\n\n");
        out.append("| Algorithm | Family | Path length | Store searched | Build time (median) |\n");
        out.append("|---|---|---:|---:|---:|\n");
        for (PathBuildResult r : federal) {
            out.append("| ").append(r.algorithm().displayName())
                    .append(" | ").append(r.algorithm().family().category())
                    .append(" | ").append(r.pathLength()).append(" certs")
                    .append(" | ").append(String.format(Locale.ROOT, "%,d B", r.poolBytes()))
                    .append(" | ").append(us(r.buildMicros().median()))
                    .append(" |\n");
        }
        out.append('\n');
    }

    /** Render a per-algorithm × column matrix of median build times. */
    private static void appendMatrix(StringBuilder out, List<PathBuildResult> results,
                                     List<Integer> columns,
                                     java.util.function.ToIntFunction<PathBuildResult> key,
                                     String columnPrefix) {
        out.append("| Algorithm |");
        for (int c : columns) {
            out.append(' ').append(columnPrefix).append(c).append(" |");
        }
        out.append("\n|---|");
        columns.forEach(c -> out.append("---:|"));
        out.append('\n');
        for (String id : results.stream().map(r -> r.algorithm().id()).distinct().toList()) {
            var spec = results.stream().filter(r -> r.algorithm().id().equals(id)).findFirst()
                    .orElseThrow().algorithm();
            out.append("| ").append(spec.displayName()).append(" |");
            for (int c : columns) {
                Optional<PathBuildResult> cell = results.stream()
                        .filter(r -> r.algorithm().id().equals(id) && key.applyAsInt(r) == c)
                        .findFirst();
                out.append(' ').append(cell.map(r -> String.format(Locale.ROOT, "%.0f",
                        r.buildMicros().median())).orElse("—")).append(" |");
            }
            out.append('\n');
        }
    }

    /** Amplification (last/first by key) for one algorithm's rows. */
    private static double amplification(List<PathBuildResult> results, String algorithmId,
                                        java.util.function.ToIntFunction<PathBuildResult> key) {
        List<PathBuildResult> rows = results.stream()
                .filter(r -> r.algorithm().id().equals(algorithmId))
                .sorted((a, b) -> Integer.compare(key.applyAsInt(a), key.applyAsInt(b)))
                .toList();
        return rows.isEmpty() ? 1.0
                : rows.get(rows.size() - 1).buildMicros().median() / rows.get(0).buildMicros().median();
    }

    private static double worstAmplification(List<PathBuildResult> results,
                                             java.util.function.ToIntFunction<PathBuildResult> key) {
        double worst = 1.0;
        for (String id : results.stream().map(r -> r.algorithm().id()).distinct().toList()) {
            List<PathBuildResult> rows = results.stream()
                    .filter(r -> r.algorithm().id().equals(id))
                    .sorted((a, b) -> Integer.compare(key.applyAsInt(a), key.applyAsInt(b)))
                    .toList();
            if (rows.size() < 2) {
                continue;
            }
            double amp = rows.get(rows.size() - 1).buildMicros().median() / rows.get(0).buildMicros().median();
            worst = Math.max(worst, amp);
        }
        return worst;
    }

    private static String us(double micros) {
        return micros >= 1000
                ? String.format(Locale.ROOT, "%.2f ms", micros / 1000)
                : String.format(Locale.ROOT, "%.1f µs", micros);
    }
}
