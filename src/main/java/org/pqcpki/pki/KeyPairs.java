package org.pqcpki.pki;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.pqcpki.algo.AlgorithmSpec;
import org.pqcpki.util.DeterministicSecureRandom;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

/**
 * Generates key pairs for an {@link AlgorithmSpec} through the BouncyCastle provider, seeded for
 * reproducibility.
 *
 * <p>Seeding takes two routes because BouncyCastle draws key-generation randomness from two places. The
 * classical generators accept a {@link SecureRandom} through {@code initialize}; the post-quantum
 * generators, initialised only by their algorithm name, instead draw from the process-wide generator in
 * {@code CryptoServicesRegistrar}. Setting both from the same seed makes ML-DSA, SLH-DSA, EC and RSA
 * generation reproducible. The composite generators pull their classical half from the JCA layer's own
 * source regardless, so their key <em>values</em> vary run to run — but a composite certificate's size
 * is fixed by its parameter set, and size is all the measurement reads.
 */
public final class KeyPairs {

    public static final String PROVIDER = "BC";

    private KeyPairs() {
    }

    /**
     * Generate a key pair for {@code spec}, seeded from {@code seed}.
     *
     * <p>Each call re-seeds the process-wide generator so that a hierarchy's keys depend only on the
     * seed and the order in which they are drawn, independent of anything else running in the JVM.
     */
    public static KeyPair generate(AlgorithmSpec spec, long seed) {
        SecureRandom random = new DeterministicSecureRandom(seed);
        CryptoServicesRegistrar.setSecureRandom(random);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(spec.keyGenAlgorithm(), PROVIDER);
            switch (spec.family()) {
                case CLASSICAL_EC ->
                        kpg.initialize(new ECGenParameterSpec(spec.keyGenParameter()), random);
                case CLASSICAL_RSA ->
                        kpg.initialize(Integer.parseInt(spec.keyGenParameter()), random);
                default -> {
                    // ML-DSA / SLH-DSA / composite: the algorithm name fully determines the parameters,
                    // and randomness comes from the registrar seeded above.
                }
            }
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            throw new IllegalStateException(
                    "BouncyCastle could not provide a key generator for " + spec.displayName()
                            + " (keyGen=" + spec.keyGenAlgorithm() + ")", e);
        } catch (java.security.InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(
                    "Invalid key-generation parameter '" + spec.keyGenParameter() + "' for "
                            + spec.displayName(), e);
        }
    }
}
