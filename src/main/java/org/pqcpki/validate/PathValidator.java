package org.pqcpki.validate;

import org.pqcpki.pki.Hierarchy;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * Validates a certificate chain the way a standard Java application does: through the JDK's own
 * {@code PKIX} {@link CertPathValidator}, with the root as the trust anchor and revocation checking
 * disabled.
 *
 * <p>The JDK validator is used deliberately (design §5). It is the engine a real application reaches for,
 * and it validates post-quantum and composite chains by delegating each signature verification to the
 * registered BouncyCastle provider — confirmed during de-risking. Using it, rather than BouncyCastle's
 * own validator, keeps the measurement representative of production Java PKI.
 *
 * <p>Revocation is disabled on purpose: OCSP and CRL checks are network operations whose cost is
 * unrelated to the cryptography under study. Disabling them isolates the thing being measured —
 * cryptographic path validation — from the thing that is not.
 *
 * <p>An instance is bound to one hierarchy and is reusable across many timed validations; it rebuilds no
 * per-call state beyond what {@code validate} requires, so repeated calls measure steady-state cost.
 */
public final class PathValidator {

    private final CertPath certPath;
    private final PKIXParameters parameters;
    private final CertPathValidator validator;

    public PathValidator(Hierarchy hierarchy) {
        try {
            this.certPath = CertificateFactory.getInstance("X.509")
                    .generateCertPath(hierarchy.transmittedChain());
            this.parameters = new PKIXParameters(Set.of(new TrustAnchor(hierarchy.root(), null)));
            this.parameters.setRevocationEnabled(false);
            this.validator = CertPathValidator.getInstance("PKIX");
        } catch (CertificateException | InvalidAlgorithmParameterException
                 | NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "could not set up PKIX validation for a " + hierarchy.algorithm().displayName()
                            + " hierarchy", e);
        }
    }

    /** The provider backing the validator itself (the JDK's {@code SUN}), recorded in results. */
    public String validatorProvider() {
        return validator.getProvider().getName();
    }

    /**
     * Validate the chain once. Throws if the chain does not validate — which, for a correctly built
     * hierarchy, only happens if the provider cannot verify the signature algorithm, so a throw here is
     * a setup failure, not a benchmark result.
     */
    public void validateOnce() {
        try {
            validator.validate(certPath, parameters);
        } catch (CertPathValidatorException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("a hierarchy that should validate did not", e);
        }
    }
}
