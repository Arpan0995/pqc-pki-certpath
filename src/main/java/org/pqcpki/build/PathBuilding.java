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
    private static final int WARMUP = 100;
    private static final int ITERATIONS = 1000;

    /** Representative algorithms: classical baselines, a lattice choice, and the fast/slow hash extremes. */
    private static final List<String> ALGORITHMS = List.of(
            "ecdsa-p256", "rsa-3072", "ml-dsa-65", "slh-dsa-sha2-128f", "slh-dsa-sha2-256f");

    private static final List<Integer> BRANCHING = List.of(1, 2, 4, 8, 16, 32);
    private static final int FEDERAL_DECOYS = 4;

    private PathBuilding() {
    }

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        Path out = args.length > 0 ? Path.of(args[0]) : Path.of("results");
        Files.createDirectories(out);

        System.out.printf("Path building: %s%n", Environment.jvm());
        CrossCertModel model = new CrossCertModel(SEED);

        List<PathBuildResult> branching = runBranching(model);
        List<PathBuildResult> federal = runFederalBridge(model);

        String report = PathBuildReport.render(branching, federal, WARMUP, ITERATIONS);
        Path file = out.resolve("PATH-BUILDING.md");
        Files.writeString(file, report);
        System.out.printf("%nWrote %s%n", file);
    }

    private static List<PathBuildResult> runBranching(CrossCertModel model) {
        System.out.println("\n[1/2] Branching sweep — build time vs number of candidate issuers");
        List<PathBuildResult> results = new ArrayList<>();
        for (String id : ALGORITHMS) {
            AlgorithmSpec spec = Algorithms.byId(id);
            for (int k : BRANCHING) {
                results.add(measure(model.branching(spec, k)));
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

    private static List<PathBuildResult> runFederalBridge(CrossCertModel model) {
        System.out.println("\n[2/2] Federal Bridge — realistic depth-5 cross-certified path");
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
