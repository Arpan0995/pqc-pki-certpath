package org.pqcpki.tls;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.pqcpki.algo.AlgorithmSpec;
import org.pqcpki.algo.Algorithms;
import org.pqcpki.env.Environment;
import org.pqcpki.pki.CertificateProfile;
import org.pqcpki.pki.HierarchyBuilder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

/**
 * The TLS readiness experiment (design §13): can a Java TLS 1.3 stack actually authenticate with
 * post-quantum certificates, and at what chain size do handshakes break?
 *
 * <p>Two orthogonal experiments, each isolating one failure axis:
 *
 * <ol>
 *   <li><b>Authentication.</b> For each algorithm and each JSSE provider (the JDK's {@code SunJSSE} and
 *       BouncyCastle's {@code BCJSSE}), attempt a real loopback handshake with a leaf signed by that
 *       algorithm. Classical algorithms are the control; the question is whether the PQC ones can be
 *       negotiated at all.
 *   <li><b>Size.</b> Using ECDSA certificates — which authenticate on both providers — grown to the
 *       measured size of each algorithm's real 3-tier chain, find where the handshake crosses
 *       {@code jdk.tls.maxHandshakeMessageSize} and fails on size alone.
 * </ol>
 */
public final class TlsReadiness {

    private static final long SEED = 20260717;
    private static final List<String> PROVIDERS = List.of("SunJSSE", "BCJSSE");

    private TlsReadiness() {
    }

    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(new BouncyCastleJsseProvider());
        // Quiet BCJSSE's java.util.logging so the console shows only our results.
        java.util.logging.Logger.getLogger("org.bouncycastle").setLevel(java.util.logging.Level.OFF);

        Path out = args.length > 0 ? Path.of(args[0]) : Path.of("results");
        Files.createDirectories(out);

        System.out.printf("TLS readiness: %s%n", Environment.jvm());

        List<AuthRow> auth = runAuthExperiment();
        List<SizeRow> size = runSizeExperiment();

        String report = TlsReport.render(auth, size);
        Path file = out.resolve("TLS-READINESS.md");
        Files.writeString(file, report);
        System.out.printf("%nWrote %s%n", file);
    }

    /** One (algorithm, provider) authentication attempt. */
    public record AuthRow(AlgorithmSpec algorithm, String provider, HandshakeOutcome outcome) {
    }

    /** One size point: a chain the size of {algorithm}'s real 3-tier chain, ECDSA-authenticated. */
    public record SizeRow(AlgorithmSpec algorithm, int targetBytes, HandshakeOutcome outcome) {
    }

    private static List<AuthRow> runAuthExperiment() {
        System.out.println("\n[1/2] Authentication — can JSSE negotiate the leaf's signature scheme?");
        List<AuthRow> rows = new ArrayList<>();
        for (AlgorithmSpec spec : Algorithms.all()) {
            TlsChains.ServerChain chain = TlsChains.authChain(spec, SEED);
            for (String provider : PROVIDERS) {
                HandshakeOutcome outcome = new LoopbackHandshake(provider)
                        .attempt(chain.chain(), chain.leafKey(), chain.trustAnchor());
                rows.add(new AuthRow(spec, provider, outcome));
                System.out.printf("    %-28s %-8s %s%n", spec.displayName(), provider,
                        outcome.succeeded() ? "OK" : outcome.category() + " (" + outcome.detail() + ")");
            }
        }
        return rows;
    }

    private static List<SizeRow> runSizeExperiment() {
        System.out.println("\n[2/2] Size — at what real-chain size does the handshake break?");
        HierarchyBuilder builder = new HierarchyBuilder(CertificateProfile.standard(), SEED);
        List<SizeRow> rows = new ArrayList<>();
        for (AlgorithmSpec spec : Algorithms.all()) {
            int target = transmittedChainBytes(builder, spec);
            TlsChains.ServerChain chain = TlsChains.sizedEcChain(target, SEED);
            HandshakeOutcome outcome = new LoopbackHandshake("SunJSSE")
                    .attempt(chain.chain(), chain.leafKey(), chain.trustAnchor());
            rows.add(new SizeRow(spec, chain.transmittedBytes(), outcome));
            System.out.printf("    ~%-28s %,7d B  %s%n",
                    spec.displayName() + " chain", chain.transmittedBytes(),
                    outcome.succeeded() ? "OK" : outcome.category() + " (" + outcome.detail() + ")");
        }
        return rows;
    }

    /** The 3-tier transmitted chain size (leaf + intermediate) for an algorithm, from the real hierarchy. */
    private static int transmittedChainBytes(HierarchyBuilder builder, AlgorithmSpec spec) {
        var certs = builder.build(spec, 3).transmittedChain();
        try {
            int sum = 0;
            for (var c : certs) {
                sum += c.getEncoded().length;
            }
            return sum;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
