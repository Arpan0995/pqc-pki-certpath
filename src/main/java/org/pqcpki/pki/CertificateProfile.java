package org.pqcpki.pki;

import java.time.Duration;

/**
 * The single certificate profile applied to every algorithm (design §2). Holding it fixed is what makes
 * the size and timing comparisons fair: any difference between an ECDSA chain and an ML-DSA chain is
 * then attributable to the cryptography, never to a longer distinguished name or an extra extension.
 *
 * <p>The profile is deliberately minimal and realistic for a CA hierarchy — BasicConstraints and
 * KeyUsage, the two extensions path validation actually consults — so the measured overhead is the
 * cryptography plus the unavoidable X.509 scaffolding, with nothing incidental inflating it.
 *
 * @param notBeforeSkew how far before "now" each certificate's validity starts (clock-skew tolerance)
 * @param validity      how long each certificate remains valid
 */
public record CertificateProfile(Duration notBeforeSkew, Duration validity) {

    /** A standard long-lived hierarchy: validity comfortably brackets any benchmark run. */
    public static CertificateProfile standard() {
        return new CertificateProfile(Duration.ofDays(1), Duration.ofDays(3650));
    }
}
