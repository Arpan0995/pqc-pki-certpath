package org.pqcpki.tls;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Light checks on capability detection. Deliberately JDK-version-agnostic: the unit test must pass on
 * whatever JDK runs it, so it asserts self-consistency, not a particular JDK's feature set (the JDK 21
 * vs 27 contrast is measured by running the harness, not asserted here).
 */
class JsseCapabilitiesTest {

    @Test
    @DisplayName("capability detection does not crash and is self-consistent")
    void selfConsistent() {
        JsseCapabilities caps = JsseCapabilities.ofDefaultProvider();
        assertNotNull(caps.summary());
        // A boolean flag must agree with its list.
        assertEquals(!caps.postQuantumKeyExchange().isEmpty(), caps.hasPostQuantumKeyExchange());
        assertEquals(!caps.postQuantumSignatureSchemes().isEmpty(), caps.hasPostQuantumSignatures());
    }

    @Test
    @DisplayName("summary names the two halves of the transition separately")
    void summaryNamesBothHalves() {
        String summary = JsseCapabilities.ofDefaultProvider().summary();
        // Whatever the JDK supports, the report always distinguishes key exchange from signatures.
        org.junit.jupiter.api.Assertions.assertTrue(summary.contains("key exchange"), summary);
        org.junit.jupiter.api.Assertions.assertTrue(summary.contains("signatures"), summary);
    }
}
