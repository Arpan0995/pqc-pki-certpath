package org.pqcpki.pki;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.pqcpki.algo.AlgorithmSpec;
import org.pqcpki.algo.Algorithms;
import org.pqcpki.measure.CertificateSize;
import org.pqcpki.validate.PathValidator;

import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Checks that every registered algorithm builds a valid, self-consistent hierarchy. This is the control
 * behind every number the study reports: if a hierarchy did not actually chain and validate, its size
 * and timing figures would be measuring something that is not a working certificate path.
 */
class HierarchyBuilderTest {

    private static final long SEED = 4242;

    @BeforeAll
    static void registerProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    static List<String> algorithmIds() {
        return Algorithms.ids();
    }

    private static HierarchyBuilder builder() {
        return new HierarchyBuilder(CertificateProfile.standard(), SEED);
    }

    @ParameterizedTest
    @MethodSource("algorithmIds")
    @DisplayName("every algorithm builds a 3-tier hierarchy that validates under PKIX")
    void hierarchyValidates(String id) {
        AlgorithmSpec spec = Algorithms.byId(id);
        Hierarchy hierarchy = builder().build(spec, 3);
        // If the JDK PKIX validator or the BC provider could not handle this algorithm, this throws.
        assertDoesNotThrow(() -> new PathValidator(hierarchy).validateOnce(),
                id + " built a hierarchy that did not validate");
    }

    @ParameterizedTest
    @MethodSource("algorithmIds")
    @DisplayName("the transmitted chain is leaf-first and excludes the root")
    void transmittedChainShape(String id) {
        Hierarchy hierarchy = builder().build(Algorithms.byId(id), 3);
        List<X509Certificate> transmitted = hierarchy.transmittedChain();
        assertEquals(hierarchy.tiers() - 1, transmitted.size(), "root must not be transmitted");
        assertEquals(hierarchy.leaf(), transmitted.get(0), "chain must be leaf-first");
        assertTrue(transmitted.stream().noneMatch(c -> c.equals(hierarchy.root())),
                "the trust anchor must never appear in the transmitted chain");
    }

    @Test
    @DisplayName("hierarchies are reproducible from the seed (certificate encodings are identical)")
    void reproducible() throws Exception {
        // Reproducibility is what lets any reported size be regenerated. PQC/EC/RSA keys are seeded,
        // so their certificates are byte-identical across builds.
        Hierarchy a = builder().build(Algorithms.byId("ml-dsa-65"), 3);
        Hierarchy b = builder().build(Algorithms.byId("ml-dsa-65"), 3);
        for (int i = 0; i < a.certificates().size(); i++) {
            assertTrue(java.util.Arrays.equals(
                            a.certificates().get(i).getEncoded(), b.certificates().get(i).getEncoded()),
                    "certificate " + i + " differs across builds with the same seed");
        }
    }

    @Test
    @DisplayName("SLH-DSA cost is almost entirely signature; ML-DSA splits key and signature")
    void decompositionMatchesFamilyShape() {
        // The RQ3 contrast, pinned: hash-based signatures have tiny keys and dominant signatures.
        CertificateSize slh = CertificateSize.of(
                builder().build(Algorithms.byId("slh-dsa-sha2-128f"), 2).leaf());
        CertificateSize mldsa = CertificateSize.of(
                builder().build(Algorithms.byId("ml-dsa-65"), 2).leaf());

        assertTrue(slh.signatureBytes() > 15 * slh.publicKeyBytes(),
                "SLH-DSA signature should dwarf its public key");
        assertTrue(slh.signatureBytes() > 0.9 * slh.totalBytes(),
                "SLH-DSA should be almost entirely signature");
        assertTrue(mldsa.publicKeyBytes() > slh.publicKeyBytes() * 10,
                "ML-DSA's public key should be far larger than SLH-DSA's");
        assertEquals(mldsa.totalBytes(),
                mldsa.publicKeyBytes() + mldsa.signatureBytes() + mldsa.overheadBytes(),
                "decomposition must account for every byte");
    }

    @Test
    @DisplayName("a 4-tier chain transmits more than a 2-tier chain of the same algorithm")
    void deeperChainsAreLarger() {
        int two = builder().build(Algorithms.byId("ml-dsa-65"), 2).transmittedChain().stream()
                .mapToInt(HierarchyBuilderTest::encodedLength).sum();
        int four = builder().build(Algorithms.byId("ml-dsa-65"), 4).transmittedChain().stream()
                .mapToInt(HierarchyBuilderTest::encodedLength).sum();
        assertTrue(four > two, "a deeper chain must transmit more bytes");
    }

    @Test
    @DisplayName("fewer than two tiers is rejected")
    void tooFewTiers() {
        assertNotEquals(null, assertDoesNotThrow(() -> builder().build(Algorithms.byId("ml-dsa-44"), 2)));
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class,
                () -> builder().build(Algorithms.byId("ml-dsa-44"), 1));
    }

    private static int encodedLength(X509Certificate c) {
        try {
            return c.getEncoded().length;
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
