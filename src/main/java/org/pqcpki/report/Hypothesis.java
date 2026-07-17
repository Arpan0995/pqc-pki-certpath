package org.pqcpki.report;

/**
 * The verdict on one pre-registered hypothesis (design §4), scored mechanically from the measurements so
 * that a prediction cannot be softened after the numbers arrive.
 *
 * @param id        the hypothesis label, e.g. {@code H1}
 * @param statement what was predicted, before data collection
 * @param supported whether the measurements bore it out
 * @param evidence  the numbers the verdict rests on, so a reader can check it
 */
public record Hypothesis(String id, String statement, boolean supported, String evidence) {

    static Hypothesis of(String id, String statement, boolean supported, String evidence) {
        return new Hypothesis(id, statement, supported, evidence);
    }

    public String verdict() {
        return supported ? "supported" : "not supported";
    }
}
