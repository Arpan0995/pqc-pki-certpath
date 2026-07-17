package org.pqcpki.tls;

/**
 * What happened when a loopback TLS 1.3 handshake was attempted, classified into the categories the
 * readiness experiment distinguishes (design §13).
 *
 * <p>The two failure categories are the point of the experiment, and they are orthogonal — a chain can
 * fail authentication regardless of size, or fail on size regardless of algorithm:
 *
 * <ul>
 *   <li>{@link Category#AUTH_FAILURE} — the peers could not agree on an authentication method, because
 *       the certificate's signature scheme is not one JSSE offers. This is where PQC certificates fail
 *       today: their TLS 1.3 signature-scheme codepoints are unimplemented.
 *   <li>{@link Category#SIZE_LIMIT} — the Certificate message exceeded
 *       {@code jdk.tls.maxHandshakeMessageSize} and was rejected before validation. This is where large
 *       chains fail, whatever signed them.
 * </ul>
 *
 * @param category   the classified result
 * @param chainBytes the certificate chain the server actually sent (0 if the handshake failed too early
 *                   to observe it)
 * @param detail     the protocol/cipher on success, or the root-cause message on failure
 */
public record HandshakeOutcome(Category category, int chainBytes, String detail) {

    public enum Category {
        /** The handshake completed and the chain validated. */
        SUCCESS,
        /** No compatible authentication — the certificate's signature scheme is unsupported by JSSE. */
        AUTH_FAILURE,
        /** The Certificate message exceeded the JDK's maximum handshake message size. */
        SIZE_LIMIT,
        /** Any other failure (recorded verbatim, not silently bucketed into the two above). */
        OTHER_FAILURE
    }

    public boolean succeeded() {
        return category == Category.SUCCESS;
    }

    static HandshakeOutcome success(int chainBytes, String protocol) {
        return new HandshakeOutcome(Category.SUCCESS, chainBytes, protocol);
    }

    /** Classify a failure from its root-cause throwable message. */
    static HandshakeOutcome failure(Throwable rootCause) {
        String message = rootCause.getMessage() == null ? rootCause.getClass().getSimpleName()
                : rootCause.getMessage();
        Category category = classify(message);
        return new HandshakeOutcome(category, 0, rootCause.getClass().getSimpleName() + ": " + message);
    }

    private static Category classify(String message) {
        String lower = message.toLowerCase();
        if (lower.contains("exceeds the maximum allowed size") || lower.contains("max_handshake")) {
            return Category.SIZE_LIMIT;
        }
        if (lower.contains("handshake_failure") || lower.contains("no cipher")
                || lower.contains("unable to find") || lower.contains("no available authentication")) {
            return Category.AUTH_FAILURE;
        }
        return Category.OTHER_FAILURE;
    }
}
