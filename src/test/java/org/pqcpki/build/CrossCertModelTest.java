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
        var k2 = model.branching(Algorithms.byId("ecdsa-p256"), 2);
        var k16 = model.branching(Algorithms.byId("ecdsa-p256"), 16);

        assertEquals(2, k2.candidateIssuers());
        assertEquals(16, k16.candidateIssuers());
        // pool = k cross-certs + 1 leaf.
        assertEquals(3, k2.pool().size());
        assertEquals(17, k16.pool().size());

        // The whole point: a path exists through the one valid cross-certificate among the k candidates.
        CertPath path = new PathBuildBenchmark(k16).buildOnce();
        assertEquals(2, path.getCertificates().size(), "leaf + valid cross-cert");
    }

    @Test
    @DisplayName("the branching scenario is solvable for a post-quantum algorithm too")
    void branchingSolvableForPqc() {
        CrossCertScenario scenario = new CrossCertModel(SEED).branching(Algorithms.byId("ml-dsa-65"), 8);
        CertPath path = new PathBuildBenchmark(scenario).buildOnce();
        assertTrue(path.getCertificates().size() >= 2);
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
