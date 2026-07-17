package org.pqcpki.algo;

/**
 * One signature algorithm under measurement, with everything needed to generate a key pair and sign a
 * certificate with it through BouncyCastle's JCA layer.
 *
 * <p>The two JCA names are kept separate on purpose, because they diverge for the classical algorithms:
 * an ECDSA certificate is generated from an {@code "EC"} key generator but signed with
 * {@code "SHA256withECDSA"}. For the post-quantum and composite algorithms the two names coincide (the
 * scheme is its own signature algorithm), and {@link #keyGenParameter} is absent.
 *
 * @param id             short stable identifier for filenames and CSV rows, e.g. {@code ml-dsa-65}
 * @param displayName    human-readable name for reports, e.g. {@code ML-DSA-65}
 * @param family         the family it is grouped and initialised under
 * @param keyGenAlgorithm JCA {@code KeyPairGenerator} name, e.g. {@code ML-DSA-65}, {@code EC}, {@code RSA}
 * @param keyGenParameter curve name ({@code secp256r1}) or RSA modulus size ({@code 3072}); null for PQC
 * @param signatureAlgorithm JCA signature name for {@code JcaContentSignerBuilder}, e.g.
 *                           {@code ML-DSA-65}, {@code SHA256withECDSA}
 */
public record AlgorithmSpec(
        String id,
        String displayName,
        Family family,
        String keyGenAlgorithm,
        String keyGenParameter,
        String signatureAlgorithm) {

    /** A pure post-quantum or composite algorithm signs with the same name it is generated under. */
    static AlgorithmSpec pqc(String id, String name, Family family) {
        return new AlgorithmSpec(id, name, family, name, null, name);
    }

    /** An ECDSA algorithm over a named curve. */
    static AlgorithmSpec ecdsa(String id, String displayName, String curve, String signatureAlgorithm) {
        return new AlgorithmSpec(id, displayName, Family.CLASSICAL_EC, "EC", curve, signatureAlgorithm);
    }

    /** An RSA algorithm of a given modulus size. */
    static AlgorithmSpec rsa(String id, String displayName, int modulusBits, String signatureAlgorithm) {
        return new AlgorithmSpec(id, displayName, Family.CLASSICAL_RSA, "RSA",
                Integer.toString(modulusBits), signatureAlgorithm);
    }

    public boolean isClassical() {
        return family.isClassical();
    }
}
