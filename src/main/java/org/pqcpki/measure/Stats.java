package org.pqcpki.measure;

import java.util.Arrays;

/**
 * Robust summary statistics for a set of timing samples.
 *
 * <p>The median and inter-quartile range are reported rather than the mean and standard deviation,
 * because validation-time samples are not normally distributed: JIT compilation, garbage collection and
 * OS scheduling produce a right-skewed distribution with occasional large outliers. A mean would chase
 * those outliers; the median is what a run actually spends most of its time doing, and the IQR states
 * the spread without being dominated by a single slow sample (design §5).
 *
 * @param count  number of samples
 * @param min    smallest sample
 * @param median 50th percentile
 * @param p25    25th percentile
 * @param p75    75th percentile
 * @param max    largest sample
 */
public record Stats(int count, double min, double p25, double median, double p75, double max) {

    /** Summarise {@code samples}; the array is copied and sorted, not modified. */
    public static Stats of(double[] samples) {
        if (samples.length == 0) {
            throw new IllegalArgumentException("no samples to summarise");
        }
        double[] sorted = samples.clone();
        Arrays.sort(sorted);
        return new Stats(
                sorted.length,
                sorted[0],
                percentile(sorted, 25),
                percentile(sorted, 50),
                percentile(sorted, 75),
                sorted[sorted.length - 1]);
    }

    /** The inter-quartile range, p75 − p25: the spread of the middle half of the samples. */
    public double iqr() {
        return p75 - p25;
    }

    /** Linear-interpolation percentile on already-sorted data. */
    private static double percentile(double[] sorted, double p) {
        if (sorted.length == 1) {
            return sorted[0];
        }
        double rank = (p / 100.0) * (sorted.length - 1);
        int lo = (int) Math.floor(rank);
        int hi = (int) Math.ceil(rank);
        if (lo == hi) {
            return sorted[lo];
        }
        double frac = rank - lo;
        return sorted[lo] * (1 - frac) + sorted[hi] * frac;
    }
}
