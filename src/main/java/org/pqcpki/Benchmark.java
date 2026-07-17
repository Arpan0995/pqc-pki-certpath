package org.pqcpki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.pqcpki.algo.AlgorithmSpec;
import org.pqcpki.algo.Algorithms;
import org.pqcpki.env.Environment;
import org.pqcpki.measure.CertificateSize;
import org.pqcpki.measure.Stats;
import org.pqcpki.measure.ValidationBenchmark;
import org.pqcpki.pki.CertificateProfile;
import org.pqcpki.pki.Hierarchy;
import org.pqcpki.pki.HierarchyBuilder;
import org.pqcpki.report.CsvWriter;
import org.pqcpki.report.HierarchyResult;
import org.pqcpki.report.ReportWriter;
import org.pqcpki.validate.PathValidator;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * The benchmark entry point: for each algorithm and tier depth, generate a certificate hierarchy,
 * measure its sizes, time its PKIX path validation, and write the report and CSV (design §5).
 *
 * <pre>{@code
 * java -jar target/pqc-pki.jar [options]
 *
 *   --algorithms=a,b    algorithm ids to run (default: all)
 *   --tiers=2,3,4       tier depths to measure (default: 2,3,4)
 *   --seed=N            key-generation seed (default: 20260717)
 *   --warmup=N          validation warmup iterations (default: 200)
 *   --iterations=N      measured validation iterations (default: 2000)
 *   --out=DIR           output directory (default: results)
 *   --no-timing         measure sizes only, skip validation timing
 * }</pre>
 */
public final class Benchmark {

    private Benchmark() {
    }

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());

        Options options;
        try {
            options = Options.parse(args);
        } catch (IllegalArgumentException e) {
            System.err.println("error: " + e.getMessage());
            System.err.println(Options.usage());
            System.exit(2);
            return;
        }

        System.out.printf("pqc-pki-certpath: BouncyCastle %s on %s%n",
                Environment.bouncyCastleVersion(), Environment.jvm());
        System.out.printf("%d algorithm(s) × tiers %s, seed %d%s%n%n",
                options.algorithms().size(), options.tiers(), options.seed(),
                options.timing() ? "" : " (sizes only)");

        HierarchyBuilder builder = new HierarchyBuilder(CertificateProfile.standard(), options.seed());
        ValidationBenchmark bench = new ValidationBenchmark(options.warmup(), options.iterations());
        List<HierarchyResult> results = new ArrayList<>();

        for (AlgorithmSpec spec : options.algorithms()) {
            System.out.println("  " + spec.displayName());
            for (int tiers : options.tiers()) {
                Hierarchy hierarchy = builder.build(spec, tiers);
                List<CertificateSize> sizes = hierarchy.certificates().stream()
                        .map(CertificateSize::of).toList();

                Stats timing = null;
                PathValidator validator = new PathValidator(hierarchy);
                validator.validateOnce(); // fail fast if this algorithm cannot be validated at all
                if (options.timing()) {
                    timing = bench.measure(validator);
                }
                HierarchyResult result = new HierarchyResult(
                        spec, tiers, sizes, timing, validator.validatorProvider());
                results.add(result);

                System.out.printf("    %d-tier: chain %,d B, cert %,d B%s%n",
                        tiers, result.transmittedChainBytes(), result.leaf().totalBytes(),
                        timing != null
                                ? String.format(", validate %.1f µs", timing.median()) : "");
            }
        }

        Path out = options.outputDir();
        Files.createDirectories(out);
        Path report = out.resolve("PKI-RESULTS.md");
        Path csv = out.resolve("pki-results.csv");
        Files.writeString(report,
                ReportWriter.render(results, options.seed(), options.warmup(), options.iterations()));
        Files.writeString(csv, CsvWriter.render(results));

        System.out.printf("%nWrote %s%n      %s%n", report, csv);
    }

    /**
     * Parsed command line.
     *
     * @param algorithms algorithms to measure
     * @param tiers      tier depths to measure
     * @param seed       key-generation seed
     * @param warmup     validation warmup iterations
     * @param iterations measured validation iterations
     * @param outputDir  where the report and CSV are written
     * @param timing     whether to collect validation timing
     */
    record Options(List<AlgorithmSpec> algorithms, List<Integer> tiers, long seed,
                   int warmup, int iterations, Path outputDir, boolean timing) {

        private static final long DEFAULT_SEED = 20260717;
        private static final int DEFAULT_WARMUP = 200;
        private static final int DEFAULT_ITERATIONS = 2000;
        private static final List<Integer> DEFAULT_TIERS = List.of(2, 3, 4);

        static Options parse(String[] args) {
            List<AlgorithmSpec> algorithms = Algorithms.all();
            List<Integer> tiers = DEFAULT_TIERS;
            long seed = DEFAULT_SEED;
            int warmup = DEFAULT_WARMUP;
            int iterations = DEFAULT_ITERATIONS;
            Path outputDir = Path.of("results");
            boolean timing = true;

            for (String arg : args) {
                if (arg.startsWith("--algorithms=")) {
                    algorithms = parseAlgorithms(value(arg));
                } else if (arg.startsWith("--tiers=")) {
                    tiers = parseTiers(value(arg));
                } else if (arg.startsWith("--seed=")) {
                    seed = Long.parseLong(value(arg));
                } else if (arg.startsWith("--warmup=")) {
                    warmup = nonNegative(value(arg), "--warmup");
                } else if (arg.startsWith("--iterations=")) {
                    iterations = positive(value(arg), "--iterations");
                } else if (arg.startsWith("--out=")) {
                    outputDir = Path.of(value(arg));
                } else if (arg.equals("--no-timing")) {
                    timing = false;
                } else {
                    throw new IllegalArgumentException("unknown option: " + arg);
                }
            }
            return new Options(algorithms, tiers, seed, warmup, iterations, outputDir, timing);
        }

        private static List<AlgorithmSpec> parseAlgorithms(String value) {
            return List.of(value.split(",")).stream().map(Algorithms::byId).toList();
        }

        private static List<Integer> parseTiers(String value) {
            List<Integer> tiers = new ArrayList<>();
            for (String t : value.split(",")) {
                int n = Integer.parseInt(t.trim());
                if (n < 2) {
                    throw new IllegalArgumentException("tiers must be at least 2, got " + n);
                }
                tiers.add(n);
            }
            return List.copyOf(tiers);
        }

        private static String value(String arg) {
            return arg.substring(arg.indexOf('=') + 1);
        }

        private static int positive(String value, String option) {
            int parsed = Integer.parseInt(value);
            if (parsed <= 0) {
                throw new IllegalArgumentException(option + " must be positive, got " + parsed);
            }
            return parsed;
        }

        private static int nonNegative(String value, String option) {
            int parsed = Integer.parseInt(value);
            if (parsed < 0) {
                throw new IllegalArgumentException(option + " must be non-negative, got " + parsed);
            }
            return parsed;
        }

        static String usage() {
            return """
                    usage: java -jar pqc-pki.jar [options]
                      --algorithms=a,b    algorithm ids (default: all)
                      --tiers=2,3,4       tier depths (default: 2,3,4)
                      --seed=N            key-generation seed (default: %d)
                      --warmup=N          validation warmup iterations (default: %d)
                      --iterations=N      measured validation iterations (default: %d)
                      --out=DIR           output directory (default: results)
                      --no-timing         sizes only, skip validation timing

                    algorithms:
                    %s"""
                    .formatted(DEFAULT_SEED, DEFAULT_WARMUP, DEFAULT_ITERATIONS,
                            String.join("\n", Algorithms.ids().stream().map(s -> "  " + s).toList()));
        }
    }
}
