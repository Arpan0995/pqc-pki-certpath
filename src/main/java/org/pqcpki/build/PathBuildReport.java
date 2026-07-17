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

    public static String render(List<PathBuildResult> branching, List<PathBuildResult> federal,
                                int warmup, int iterations) {
        StringBuilder out = new StringBuilder();
        out.append("# Path Building — CertPathBuilder over Cross-Certified (FPKI-Shaped) Hierarchies\n\n");
        appendProvenance(out, warmup, iterations);
        appendHeadline(out, branching, federal);
        appendBranching(out, branching);
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
                + "iterations.\n\n");
    }

    private static void appendHeadline(StringBuilder out, List<PathBuildResult> branching,
                                       List<PathBuildResult> federal) {
        out.append("## Headline\n\n");
        // Worst branching amplification: max median at highest k vs k=1, across algorithms.
        double worstAmp = 1.0;
        String worstAlg = "";
        for (String id : branching.stream().map(r -> r.algorithm().id()).distinct().toList()) {
            List<PathBuildResult> rows = branching.stream()
                    .filter(r -> r.algorithm().id().equals(id))
                    .sorted((a, b) -> Integer.compare(a.candidateIssuers(), b.candidateIssuers()))
                    .toList();
            double amp = rows.get(rows.size() - 1).buildMicros().median() / rows.get(0).buildMicros().median();
            if (amp > worstAmp) {
                worstAmp = amp;
                worstAlg = rows.get(0).algorithm().displayName();
            }
        }
        int maxK = branching.stream().mapToInt(PathBuildResult::candidateIssuers).max().orElse(0);
        if (worstAmp < 1.5) {
            out.append(String.format(Locale.ROOT,
                    "Path discovery is **robust to cross-certificate branching**: growing a bridged name "
                            + "from 1 to %d candidate issuers barely moves build time (worst case %s, "
                            + "%.1f×). The JDK builder prunes candidates by name and trust-anchor priority "
                            + "before verifying signatures, so branching does not amplify cost even for a "
                            + "slow verifier like SLH-DSA — a reassuring result for cross-certified FPKI. ",
                    maxK, worstAlg, worstAmp));
        } else {
            out.append(String.format(Locale.ROOT,
                    "Path discovery scales with the number of candidate issuers a bridged name carries: "
                            + "from 1 to %d candidates, the worst-affected algorithm (%s) grows **%.1f×**. ",
                    maxK, worstAlg, worstAmp));
        }
        Optional<PathBuildResult> slhFederal = federal.stream()
                .filter(r -> r.algorithm().family() == org.pqcpki.algo.Family.SLH_DSA
                        && r.algorithm().displayName().endsWith("F"))
                .max((a, b) -> Double.compare(a.buildMicros().median(), b.buildMicros().median()));
        Optional<PathBuildResult> classicalFederal = federal.stream()
                .filter(r -> r.algorithm().isClassical())
                .min((a, b) -> Double.compare(a.buildMicros().median(), b.buildMicros().median()));
        if (slhFederal.isPresent() && classicalFederal.isPresent()) {
            out.append(String.format(Locale.ROOT,
                    "On the realistic Federal-Bridge path, discovery costs %.0f µs for %s versus %.0f µs "
                            + "for %s — the post-quantum signature cost carries into path building, not "
                            + "just validation.",
                    slhFederal.get().buildMicros().median(), slhFederal.get().algorithm().displayName(),
                    classicalFederal.get().buildMicros().median(),
                    classicalFederal.get().algorithm().displayName()));
        }
        out.append("\n\n");
    }

    private static void appendBranching(StringBuilder out, List<PathBuildResult> branching) {
        List<Integer> ks = branching.stream().map(PathBuildResult::candidateIssuers).distinct().sorted()
                .toList();
        out.append("## Branching sweep — build time vs candidate issuers\n\n");
        out.append("A single bridged CA name issued a certificate by *k* different roots, only one of "
                + "which chains to the trust anchor. Median path-build time (µs):\n\n");
        out.append("| Algorithm |");
        for (int k : ks) {
            out.append(" k=").append(k).append(" |");
        }
        out.append("\n|---|");
        ks.forEach(k -> out.append("---:|"));
        out.append('\n');
        for (String id : branching.stream().map(r -> r.algorithm().id()).distinct().toList()) {
            var spec = branching.stream().filter(r -> r.algorithm().id().equals(id)).findFirst()
                    .orElseThrow().algorithm();
            out.append("| ").append(spec.displayName()).append(" |");
            for (int k : ks) {
                Optional<PathBuildResult> cell = branching.stream()
                        .filter(r -> r.algorithm().id().equals(id) && r.candidateIssuers() == k)
                        .findFirst();
                out.append(' ').append(cell.map(r -> String.format(Locale.ROOT, "%.1f",
                        r.buildMicros().median())).orElse("—")).append(" |");
            }
            out.append('\n');
        }
        out.append("\nIf build time is flat in *k*, the builder prunes candidates by name before verifying "
                + "signatures, and post-quantum cost does not amplify discovery. If it rises with *k*, the "
                + "builder verifies candidates it later discards, and each wasted verification costs the "
                + "algorithm's full signature-check price — which is where a slow verifier like SLH-DSA "
                + "would stand out.\n\n");
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

    private static String us(double micros) {
        return micros >= 1000
                ? String.format(Locale.ROOT, "%.2f ms", micros / 1000)
                : String.format(Locale.ROOT, "%.1f µs", micros);
    }
}
