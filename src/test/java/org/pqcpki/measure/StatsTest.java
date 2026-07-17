package org.pqcpki.measure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StatsTest {

    @Test
    @DisplayName("percentiles and range on a known sample")
    void knownSample() {
        Stats s = Stats.of(new double[]{1, 2, 3, 4, 5});
        assertEquals(5, s.count());
        assertEquals(1, s.min());
        assertEquals(5, s.max());
        assertEquals(3, s.median());
        assertEquals(2, s.p25());
        assertEquals(4, s.p75());
        assertEquals(2, s.iqr());
    }

    @Test
    @DisplayName("order does not matter — the array is sorted internally")
    void orderIndependent() {
        Stats a = Stats.of(new double[]{5, 3, 1, 4, 2});
        Stats b = Stats.of(new double[]{1, 2, 3, 4, 5});
        assertEquals(b.median(), a.median());
        assertEquals(b.p25(), a.p25());
        assertEquals(b.p75(), a.p75());
    }

    @Test
    @DisplayName("the median resists a single large outlier")
    void medianResistsOutlier() {
        // The reason the report uses the median, not the mean, over timing samples (design §5).
        Stats s = Stats.of(new double[]{10, 10, 10, 10, 10_000});
        assertEquals(10, s.median());
    }

    @Test
    @DisplayName("a single sample is its own every statistic")
    void singleSample() {
        Stats s = Stats.of(new double[]{42});
        assertEquals(42, s.median());
        assertEquals(42, s.min());
        assertEquals(42, s.max());
        assertEquals(0, s.iqr());
    }

    @Test
    @DisplayName("interpolates between ranks for even-sized samples")
    void interpolates() {
        Stats s = Stats.of(new double[]{0, 10});
        assertEquals(5, s.median());
    }

    @Test
    @DisplayName("an empty sample is rejected rather than silently zero")
    void emptyRejected() {
        assertThrows(IllegalArgumentException.class, () -> Stats.of(new double[0]));
    }
}
