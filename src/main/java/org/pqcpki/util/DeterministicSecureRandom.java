package org.pqcpki.util;

import java.security.SecureRandom;
import java.util.random.RandomGenerator;
import java.util.random.RandomGeneratorFactory;

/**
 * A {@link SecureRandom} whose output is fully determined by a seed, so that generated key pairs — and
 * therefore the certificate hierarchies built from them — are reproducible across runs. This is for
 * experiment reproducibility only; it is not cryptographically secure and must never protect real data.
 *
 * <p>BouncyCastle draws key-generation randomness through {@link SecureRandom#nextBytes(byte[])}, either
 * from an instance passed to {@code KeyPairGenerator.initialize} or from the process-wide generator set
 * via {@code CryptoServicesRegistrar.setSecureRandom}. Seeding both makes ML-DSA, SLH-DSA, EC and RSA
 * key generation reproducible; the composite generators draw their classical half from the JCA layer's
 * own source and are not bit-reproducible, but their certificate <em>sizes</em> are stable, which is
 * what the measurement depends on.
 */
public final class DeterministicSecureRandom extends SecureRandom {

    private final RandomGenerator rng;

    public DeterministicSecureRandom(long seed) {
        super();
        this.rng = RandomGeneratorFactory.of("L64X128MixRandom").create(seed);
    }

    @Override
    public void nextBytes(byte[] bytes) {
        int i = 0;
        while (i < bytes.length) {
            long r = rng.nextLong();
            for (int b = 0; b < 8 && i < bytes.length; b++, i++) {
                bytes[i] = (byte) (r & 0xFF);
                r >>>= 8;
            }
        }
    }

    @Override
    public long nextLong() {
        return rng.nextLong();
    }

    @Override
    public int nextInt() {
        return rng.nextInt();
    }

    @Override
    public byte[] generateSeed(int numBytes) {
        byte[] out = new byte[numBytes];
        nextBytes(out);
        return out;
    }
}
