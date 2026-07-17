package org.pqcpki.build;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.pqcpki.algo.AlgorithmSpec;
import org.pqcpki.algo.Algorithms;
import org.pqcpki.env.Environment;
import org.pqcpki.measure.Stats;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.security.cert.CertPath;
import java.util.ArrayList;
import java.util.List;

/**
 * The path-building experiments (design §14): how much does {@link java.security.cert.CertPathBuilder}
 * path discovery cost over cross-certified, Federal-PKI-shaped hierarchies, and does the post-quantum
 * signature cost amplify it?
 *
 * <ol>
 *   <li><b>Branching sweep.</b> One bridged CA name with a growing number of candidate issuers, only one
 *       of which chains to the anchor. Measures how discovery scales with the branching factor, per
 *       algorithm.
 *   <li><b>Federal Bridge.</b> A realistic depth-five bridged path with decoy cross-certificates,
 *       reporting the concrete migration cost.
 * </ol>
 */
public final class PathBuilding {

    private static final long SEED = 20260717;
    // Path building is milliseconds for the deep SLH-DSA cases, so a few hundred iterations already give
    // a stable median without the run taking tens of minutes.
    private static final int WARMUP = 40;
    private static final int ITERATIONS = 250;

    /** Representative algorithms: classical baselines, a lattice choice, and the fast/slow hash extremes. */
    private static final List<String> ALGORITHMS = List.of(
            "ecdsa-p256", "rsa-3072", "ml-dsa-65", "slh-dsa-sha2-128f", "slh-dsa-sha2-256f");

    private static final List<Integer> BRANCHING = List.of(1, 2, 4, 8, 16, 32);
    private static final List<Integer> DEPTHS = List.of(2, 3, 4, 5);
    private static final int BREADTH_SWEEP_DEPTH = 3;
    private static final int DEPTH_SWEEP_K = 8;
    private static final int FEDERAL_DECOYS = 4;

    private PathBuilding() {
    }

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        Path out = args.length > 0 ? Path.of(args[0]) : Path.of("results");
        Files.createDirectories(out);

        System.out.printf("Path building: %s%n", Environment.jvm());
        CrossCertModel model = new CrossCertModel(SEED);

        List<PathBuildResult> breadth = runBreadthSweep(model);
        List<PathBuildResult> depth = runDepthSweep(model);
        List<PathBuildResult> federal = runFederalBridge(model);

        String report = PathBuildReport.render(breadth, depth, federal, WARMUP, ITERATIONS);
        Path file = out.resolve("PATH-BUILDING.md");
        Files.writeString(file, report);
        System.out.printf("%nWrote %s%n", file);
    }

    /** Breadth: how many multi-hop candidate branches a bridged name has, at a fixed decoy depth. */
    private static List<PathBuildResult> runBreadthSweep(CrossCertModel model) {
        System.out.printf("%n[1/3] Breadth sweep — build time vs candidate issuers (each %d hops deep)%n",
                BREADTH_SWEEP_DEPTH);
        List<PathBuildResult> results = new ArrayList<>();
        for (String id : ALGORITHMS) {
            AlgorithmSpec spec = Algorithms.byId(id);
            for (int k : BRANCHING) {
                results.add(measure(model.branching(spec, k, BREADTH_SWEEP_DEPTH)));
            }
            PathBuildResult k1 = results.get(results.size() - BRANCHING.size());
            PathBuildResult kMax = results.get(results.size() - 1);
            System.out.printf("    %-20s k=%d..%d: %.1f -> %.1f us  (%.1fx)%n",
                    spec.displayName(), BRANCHING.get(0), BRANCHING.get(BRANCHING.size() - 1),
                    k1.buildMicros().median(), kMax.buildMicros().median(),
                    kMax.buildMicros().median() / k1.buildMicros().median());
        }
        return results;
    }

    /** Depth: how deep the discovered path is, at a fixed branching factor. */
    private static List<PathBuildResult> runDepthSweep(CrossCertModel model) {
        System.out.printf("%n[2/3] Depth sweep — build time vs path depth (k=%d candidate branches)%n",
                DEPTH_SWEEP_K);
        List<PathBuildResult> results = new ArrayList<>();
        for (String id : ALGORITHMS) {
            AlgorithmSpec spec = Algorithms.byId(id);
            for (int d : DEPTHS) {
                results.add(measure(model.branching(spec, DEPTH_SWEEP_K, d)));
            }
            PathBuildResult d0 = results.get(results.size() - DEPTHS.size());
            PathBuildResult dMax = results.get(results.size() - 1);
            System.out.printf("    %-20s depth=%d..%d: %.1f -> %.1f us  (%.1fx)%n",
                    spec.displayName(), DEPTHS.get(0), DEPTHS.get(DEPTHS.size() - 1),
                    d0.buildMicros().median(), dMax.buildMicros().median(),
                    dMax.buildMicros().median() / d0.buildMicros().median());
        }
        return results;
    }

    private static List<PathBuildResult> runFederalBridge(CrossCertModel model) {
        System.out.println("\n[3/3] Federal Bridge — realistic depth-5 cross-certified path");
        List<PathBuildResult> results = new ArrayList<>();
        for (String id : Algorithms.ids()) {
            AlgorithmSpec spec = Algorithms.byId(id);
            PathBuildResult r = measure(model.federalBridge(spec, FEDERAL_DECOYS));
            results.add(r);
            System.out.printf("    %-28s path=%d certs, build %.1f us%n",
                    spec.displayName(), r.pathLength(), r.buildMicros().median());
        }
        return results;
    }

    private static PathBuildResult measure(CrossCertScenario scenario) {
        PathBuildBenchmark benchmark = new PathBuildBenchmark(scenario);
        CertPath path = benchmark.buildOnce();
        Stats stats = benchmark.measure(WARMUP, ITERATIONS);
        return new PathBuildResult(
                scenario.name(), scenario.algorithm(), scenario.candidateIssuers(),
                scenario.pool().size(), scenario.poolBytes(),
                path.getCertificates().size(), stats);
    }
}
