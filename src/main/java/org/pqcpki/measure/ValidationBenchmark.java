package org.pqcpki.measure;

import org.pqcpki.validate.PathValidator;

/**
 * Times PKIX path validation for one hierarchy: warm up, then take many samples, and summarise them
 * robustly (design §5).
 *
 * <p>The warmup exists because the first validations of a chain on a fresh JVM are dominated by class
 * loading and JIT compilation, not by the cryptography — timing those would measure the JVM warming up,
 * not the algorithm. After warmup the interpreter has compiled the hot path and the samples reflect
 * steady-state cost, which is what the comparison between algorithms needs.
 *
 * <p>Each sample times a single {@code validate} call with {@link System#nanoTime()}. Nothing is done to
 * defeat the JIT beyond having {@code validate} throw on failure, because path validation has observable
 * side effects (it verifies signatures and walks the chain) that the compiler cannot elide.
 */
public final class ValidationBenchmark {

    private final int warmupIterations;
    private final int measuredIterations;

    public ValidationBenchmark(int warmupIterations, int measuredIterations) {
        if (measuredIterations < 1) {
            throw new IllegalArgumentException("need at least one measured iteration");
        }
        this.warmupIterations = warmupIterations;
        this.measuredIterations = measuredIterations;
    }

    /**
     * Warm up and then measure, returning per-validation times in microseconds.
     */
    public Stats measure(PathValidator validator) {
        for (int i = 0; i < warmupIterations; i++) {
            validator.validateOnce();
        }
        double[] microseconds = new double[measuredIterations];
        for (int i = 0; i < measuredIterations; i++) {
            long start = System.nanoTime();
            validator.validateOnce();
            microseconds[i] = (System.nanoTime() - start) / 1_000.0;
        }
        return Stats.of(microseconds);
    }
}
