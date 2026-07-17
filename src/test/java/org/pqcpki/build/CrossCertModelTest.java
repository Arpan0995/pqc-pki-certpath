package org.pqcpki.build;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.pqcpki.algo.Algorithms;

import java.security.Security;
import java.security.cert.CertPath;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Checks that the cross-certified scenarios are actually solvable — that a path really can be discovered
 * through them — and that the branching factor grows the store as intended. Without this, a "build time"
 * measurement could be timing a builder that fails, or a store that never had the candidates it claimed.
 */
class CrossCertModelTest {

    private static final long SEED = 20260717;

    @BeforeAll
    static void registerProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @DisplayName("the branching scenario is solvable and its store grows with k")
    void branchingSolvableAndGrows() {
        CrossCertModel model = new CrossCertModel(SEED);
        int depth = 3;
        var k2 = model.branching(Algorithms.byId("ecdsa-p256"), 2, depth);
        var k16 = model.branching(Algorithms.byId("ecdsa-p256"), 16, depth);

        assertEquals(2, k2.candidateIssuers());
        assertEquals(16, k16.candidateIssuers());
        // More candidate branches means a strictly larger store to search.
        assertTrue(k16.pool().size() > k2.pool().size(),
                "k=16 pool " + k16.pool().size() + " should exceed k=2 pool " + k2.pool().size());

        // The whole point: a path exists through the one branch that reaches the anchor.
        CertPath path = new PathBuildBenchmark(k16).buildOnce();
        assertEquals(depth + 2, path.getCertificates().size(), "leaf + bridged + depth intermediates");
    }

    @Test
    @DisplayName("multi-hop decoy branches are solvable at every depth 1..5 (no construction off-by-one)")
    void branchingSolvableAtEveryDepth() {
        CrossCertModel model = new CrossCertModel(SEED);
        for (int depth = 1; depth <= 5; depth++) {
            CrossCertScenario scenario = model.branching(Algorithms.byId("ml-dsa-65"), 4, depth);
            CertPath path = new PathBuildBenchmark(scenario).buildOnce();
            assertEquals(depth + 2, path.getCertificates().size(),
                    "depth " + depth + " should discover a path of depth+2 certificates");
        }
    }

    @Test
    @DisplayName("the Federal Bridge scenario discovers a depth-5 path through the bridge cross-cert")
    void federalBridgeSolvable() {
        CrossCertScenario scenario = new CrossCertModel(SEED)
                .federalBridge(Algorithms.byId("ml-dsa-65"), 4);
        CertPath path = new PathBuildBenchmark(scenario).buildOnce();
        // Path from leaf to (but not including) the Common Policy Root anchor: leaf, sub, agency, bridge.
        assertEquals(4, path.getCertificates().size());
        // Store carries the valid bridge cross-cert plus the four decoys plus the interior certs.
        assertTrue(scenario.pool().size() >= 4 + 3, "pool: " + scenario.pool().size());
    }

    @Test
    @DisplayName("scenarios are reproducible from the seed")
    void reproducible() {
        var a = new CrossCertModel(SEED).branching(Algorithms.byId("ml-dsa-65"), 4);
        var b = new CrossCertModel(SEED).branching(Algorithms.byId("ml-dsa-65"), 4);
        assertEquals(a.poolBytes(), b.poolBytes());
    }
}
