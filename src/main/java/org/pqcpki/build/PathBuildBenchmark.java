package org.pqcpki.build;

import org.pqcpki.measure.Stats;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathBuilder;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Set;

/**
 * Times {@link CertPathBuilder} path <em>discovery</em> for one cross-certified scenario: warm up, then
 * measure. This is the operation the validation study did not cover — finding a path through a store,
 * rather than validating one already in hand — and the place non-linear behaviour could hide, because a
 * name with several candidate issuers forces the builder to explore.
 *
 * <p>The builder and its parameters are prepared once and reused across timed builds, so repeated calls
 * measure steady-state discovery cost rather than store construction.
 */
public final class PathBuildBenchmark {

    private final CrossCertScenario scenario;
    private final CertPathBuilder builder;
    private final PKIXBuilderParameters parameters;

    public PathBuildBenchmark(CrossCertScenario scenario) {
        this.scenario = scenario;
        try {
            X509CertSelector target = new X509CertSelector();
            target.setCertificate(scenario.targetLeaf());
            this.parameters = new PKIXBuilderParameters(
                    Set.of(new TrustAnchor(scenario.trustAnchor(), null)), target);
            this.parameters.addCertStore(
                    CertStore.getInstance("Collection", new CollectionCertStoreParameters(scenario.pool())));
            this.parameters.setRevocationEnabled(false);
            this.builder = CertPathBuilder.getInstance("PKIX");
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("could not set up path building for " + scenario.name(), e);
        }
    }

    /** Build the path once, returning it. Throws if no path can be built (a scenario setup error). */
    public CertPath buildOnce() {
        try {
            CertPathBuilderResult result = builder.build(parameters);
            return result.getCertPath();
        } catch (CertPathBuilderException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(
                    "no path found for " + scenario.name() + "; the scenario is misconfigured", e);
        }
    }

    /** Warm up, then time repeated builds, returning per-build microseconds. */
    public Stats measure(int warmup, int measured) {
        for (int i = 0; i < warmup; i++) {
            buildOnce();
        }
        double[] micros = new double[measured];
        for (int i = 0; i < measured; i++) {
            long start = System.nanoTime();
            buildOnce();
            micros[i] = (System.nanoTime() - start) / 1_000.0;
        }
        return Stats.of(micros);
    }
}
