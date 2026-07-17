package org.pqcpki.tls;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tests the classification that turns a raw handshake failure into one of the two breakage axes. Getting
 * this wrong would mislabel an authentication failure as a size failure or vice versa — the whole point
 * of the experiment is to keep them apart.
 */
class HandshakeOutcomeTest {

    private static HandshakeOutcome.Category categorize(String message) {
        return HandshakeOutcome.failure(new RuntimeException(message)).category();
    }

    @Test
    @DisplayName("the JDK size-limit message is classified as SIZE_LIMIT")
    void sizeLimit() {
        assertEquals(HandshakeOutcome.Category.SIZE_LIMIT,
                categorize("The size of the handshake message (36730) exceeds the maximum allowed size (32768)"));
    }

    @Test
    @DisplayName("a handshake_failure alert is classified as AUTH_FAILURE")
    void authFailure() {
        assertEquals(HandshakeOutcome.Category.AUTH_FAILURE,
                categorize("Received fatal alert: handshake_failure"));
        assertEquals(HandshakeOutcome.Category.AUTH_FAILURE, categorize("handshake_failure(40)"));
    }

    @Test
    @DisplayName("an unrelated failure is not forced into one of the two named buckets")
    void otherFailure() {
        assertEquals(HandshakeOutcome.Category.OTHER_FAILURE, categorize("Connection reset"));
        assertEquals(HandshakeOutcome.Category.OTHER_FAILURE, categorize("Broken pipe"));
    }

    @Test
    @DisplayName("success carries the chain size and protocol")
    void success() {
        HandshakeOutcome outcome = HandshakeOutcome.success(1234, "TLSv1.3 / TLS_AES_256_GCM_SHA384");
        assertEquals(HandshakeOutcome.Category.SUCCESS, outcome.category());
        assertEquals(1234, outcome.chainBytes());
        org.junit.jupiter.api.Assertions.assertTrue(outcome.succeeded());
    }
}
