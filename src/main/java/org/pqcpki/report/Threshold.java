package org.pqcpki.report;

import java.util.List;

/**
 * A size limit that a certificate chain might cross, and the assumption it encodes (design §6). The
 * study reports these crossings because they are where a chain that is merely large becomes a chain that
 * breaks something.
 *
 * @param name        short label
 * @param bytes       the limit in bytes
 * @param description what assumes it, and what crossing it means
 */
public record Threshold(String name, int bytes, String description) {

    /**
     * The reference thresholds, smallest first. Fixed values cited from the TLS specification and the
     * JDK defaults; see design §6.
     */
    public static List<Threshold> reference() {
        return List.of(
                new Threshold("TLS record", 16_384,
                        "RFC 8446 §5.1 plaintext record limit (2^14). A larger Certificate message is "
                                + "fragmented across records; buffers and middleboxes sometimes assume "
                                + "a message fits one record."),
                new Threshold("JDK max handshake message", 32_768,
                        "jdk.tls.maxHandshakeMessageSize default. A Certificate message above this is "
                                + "rejected by the JDK TLS stack unless the property is raised."));
    }

    /** Whether a chain of {@code chainBytes} crosses this threshold. */
    public boolean isCrossedBy(int chainBytes) {
        return chainBytes > bytes;
    }
}
