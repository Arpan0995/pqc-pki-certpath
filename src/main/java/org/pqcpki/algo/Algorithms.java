package org.pqcpki.algo;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The registry of algorithms under measurement (design §2). Ordered classical → ML-DSA → SLH-DSA →
 * composite, so reports read from the incumbent baselines outward to the heaviest post-quantum options.
 *
 * <p>Every name here was confirmed against the BouncyCastle 1.85 provider during de-risking; a typo
 * would surface immediately as a {@code NoSuchAlgorithmException} when the harness builds the generator.
 */
public final class Algorithms {

    private static final Map<String, AlgorithmSpec> REGISTRY = new LinkedHashMap<>();

    static {
        // Classical baselines — what PQC replaces.
        register(AlgorithmSpec.ecdsa("ecdsa-p256", "ECDSA P-256", "secp256r1", "SHA256withECDSA"));
        register(AlgorithmSpec.rsa("rsa-3072", "RSA-3072", 3072, "SHA256withRSA"));

        // ML-DSA (FIPS 204) — lattice.
        register(AlgorithmSpec.pqc("ml-dsa-44", "ML-DSA-44", Family.ML_DSA));
        register(AlgorithmSpec.pqc("ml-dsa-65", "ML-DSA-65", Family.ML_DSA));
        register(AlgorithmSpec.pqc("ml-dsa-87", "ML-DSA-87", Family.ML_DSA));

        // SLH-DSA (FIPS 205) — hash-based. The f/s pairs bracket the size/speed trade-off.
        register(AlgorithmSpec.pqc("slh-dsa-sha2-128f", "SLH-DSA-SHA2-128F", Family.SLH_DSA));
        register(AlgorithmSpec.pqc("slh-dsa-sha2-128s", "SLH-DSA-SHA2-128S", Family.SLH_DSA));
        register(AlgorithmSpec.pqc("slh-dsa-sha2-192f", "SLH-DSA-SHA2-192F", Family.SLH_DSA));
        register(AlgorithmSpec.pqc("slh-dsa-sha2-256f", "SLH-DSA-SHA2-256F", Family.SLH_DSA));

        // Composite (IETF LAMPS) — PQC + classical carried together.
        register(AlgorithmSpec.pqc("mldsa44-ecdsa-p256", "MLDSA44-ECDSA-P256-SHA256", Family.COMPOSITE));
        register(AlgorithmSpec.pqc("mldsa65-ecdsa-p384", "MLDSA65-ECDSA-P384-SHA512", Family.COMPOSITE));
        register(AlgorithmSpec.pqc("mldsa65-rsa3072", "MLDSA65-RSA3072-PSS-SHA512", Family.COMPOSITE));
        register(AlgorithmSpec.pqc("mldsa87-ecdsa-p521", "MLDSA87-ECDSA-P521-SHA512", Family.COMPOSITE));
    }

    private Algorithms() {
    }

    private static void register(AlgorithmSpec spec) {
        REGISTRY.put(spec.id(), spec);
    }

    /** All algorithms, in registry order. */
    public static List<AlgorithmSpec> all() {
        return List.copyOf(REGISTRY.values());
    }

    /** All algorithm ids, in registry order. */
    public static List<String> ids() {
        return List.copyOf(REGISTRY.keySet());
    }

    /**
     * The algorithm with the given id.
     *
     * @throws IllegalArgumentException if no such algorithm is registered
     */
    public static AlgorithmSpec byId(String id) {
        AlgorithmSpec spec = REGISTRY.get(id);
        if (spec == null) {
            throw new IllegalArgumentException(
                    "Unknown algorithm '" + id + "'; known: " + String.join(", ", ids()));
        }
        return spec;
    }
}
