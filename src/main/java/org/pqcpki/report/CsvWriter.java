package org.pqcpki.report;

import java.util.List;
import java.util.Locale;

/**
 * Renders the results as CSV, one row per (algorithm, tier depth), so the numbers can be re-plotted or
 * re-analysed without re-running the benchmark.
 */
public final class CsvWriter {

    private static final String HEADER = String.join(",",
            "algorithm_id", "algorithm", "family", "tiers",
            "transmitted_chain_bytes", "total_hierarchy_bytes",
            "leaf_total_bytes", "leaf_public_key_bytes", "leaf_signature_bytes", "leaf_overhead_bytes",
            "validation_median_us", "validation_p25_us", "validation_p75_us",
            "validation_min_us", "validation_max_us", "validation_samples");

    private CsvWriter() {
    }

    public static String render(List<HierarchyResult> results) {
        StringBuilder out = new StringBuilder(HEADER).append('\n');
        for (HierarchyResult r : results) {
            out.append(r.algorithm().id()).append(',')
                    .append(r.algorithm().displayName()).append(',')
                    .append(r.algorithm().family().category()).append(',')
                    .append(r.tiers()).append(',')
                    .append(r.transmittedChainBytes()).append(',')
                    .append(r.totalHierarchyBytes()).append(',')
                    .append(r.leaf().totalBytes()).append(',')
                    .append(r.leaf().publicKeyBytes()).append(',')
                    .append(r.leaf().signatureBytes()).append(',')
                    .append(r.leaf().overheadBytes()).append(',')
                    .append(cell(r.hasTiming() ? r.validationMicros().median() : Double.NaN)).append(',')
                    .append(cell(r.hasTiming() ? r.validationMicros().p25() : Double.NaN)).append(',')
                    .append(cell(r.hasTiming() ? r.validationMicros().p75() : Double.NaN)).append(',')
                    .append(cell(r.hasTiming() ? r.validationMicros().min() : Double.NaN)).append(',')
                    .append(cell(r.hasTiming() ? r.validationMicros().max() : Double.NaN)).append(',')
                    .append(r.hasTiming() ? r.validationMicros().count() : 0)
                    .append('\n');
        }
        return out.toString();
    }

    private static String cell(double value) {
        return Double.isNaN(value) ? "" : String.format(Locale.ROOT, "%.3f", value);
    }
}
