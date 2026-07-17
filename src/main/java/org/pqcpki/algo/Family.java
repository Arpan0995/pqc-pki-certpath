package org.pqcpki.algo;

/**
 * The cryptographic family a signature algorithm belongs to. This groups results for reporting and,
 * for the two classical families, records how their key generators must be initialised (an elliptic
 * curve name versus an RSA modulus size).
 */
public enum Family {

    /** Classical elliptic-curve (ECDSA). Key generation takes a named-curve parameter. */
    CLASSICAL_EC("Classical"),

    /** Classical RSA. Key generation takes a modulus size in bits. */
    CLASSICAL_RSA("Classical"),

    /** Lattice-based, FIPS 204. Large public keys and large signatures. */
    ML_DSA("ML-DSA"),

    /** Hash-based, FIPS 205. Tiny public keys, very large signatures. */
    SLH_DSA("SLH-DSA"),

    /** IETF composite: a PQC and a classical signature carried together. */
    COMPOSITE("Composite");

    private final String category;

    Family(String category) {
        this.category = category;
    }

    /** The label this family is grouped under in reports; both classical families share "Classical". */
    public String category() {
        return category;
    }

    /** Whether this is one of the classical (pre-quantum) families used as a baseline. */
    public boolean isClassical() {
        return this == CLASSICAL_EC || this == CLASSICAL_RSA;
    }
}
