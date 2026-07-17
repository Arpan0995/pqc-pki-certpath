package org.pqcpki.tls;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import java.util.Arrays;
import java.util.List;

/**
 * What post-quantum capabilities the running JDK's default TLS provider actually advertises — read
 * straight from {@link SSLParameters}, so the readiness report self-documents the JDK it ran on.
 *
 * <p>This is the lens for the JDK 21 vs JDK 27 comparison (design §16). The transition has two halves,
 * and a JDK can ship one without the other: <em>key exchange</em> (an ML-KEM named group, added by
 * JEP 527 in JDK 27) and <em>authentication</em> (an ML-DSA or SLH-DSA signature scheme, still absent).
 * The certificate/PKI layer this project measures depends entirely on the second half.
 */
public final class JsseCapabilities {

    private final List<String> namedGroups;
    private final List<String> signatureSchemes;

    private JsseCapabilities(List<String> namedGroups, List<String> signatureSchemes) {
        this.namedGroups = namedGroups;
        this.signatureSchemes = signatureSchemes;
    }

    /** Read the default TLS provider's supported parameters. */
    public static JsseCapabilities ofDefaultProvider() {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, null, null);
            SSLParameters params = context.getSupportedSSLParameters();
            return new JsseCapabilities(nonNull(params.getNamedGroups()),
                    nonNull(params.getSignatureSchemes()));
        } catch (Exception e) {
            return new JsseCapabilities(List.of(), List.of());
        }
    }

    /** Named groups whose name marks an ML-KEM (post-quantum) key exchange, e.g. {@code X25519MLKEM768}. */
    public List<String> postQuantumKeyExchange() {
        return namedGroups.stream().filter(g -> normalize(g).contains("mlkem")).toList();
    }

    /** Signature schemes whose name marks an ML-DSA or SLH-DSA (post-quantum) authentication scheme. */
    public List<String> postQuantumSignatureSchemes() {
        return signatureSchemes.stream()
                .filter(s -> {
                    String n = normalize(s);
                    return n.contains("mldsa") || n.contains("slhdsa");
                })
                .toList();
    }

    public boolean hasPostQuantumKeyExchange() {
        return !postQuantumKeyExchange().isEmpty();
    }

    public boolean hasPostQuantumSignatures() {
        return !postQuantumSignatureSchemes().isEmpty();
    }

    /**
     * Whether the JDK reports its signature schemes at all. JDK 21's supported {@link SSLParameters}
     * leaves them null, so an empty list there means "unknown", not "none" — the actual JDK 21 schemes
     * are observed from the ClientHello instead, and are likewise classical.
     */
    public boolean reportsSignatureSchemes() {
        return !signatureSchemes.isEmpty();
    }

    /** A one-line summary for the report header. */
    public String summary() {
        String kex = hasPostQuantumKeyExchange()
                ? "key exchange = " + String.join(", ", postQuantumKeyExchange()) + " (present)"
                : "key exchange = none";
        String sig = !reportsSignatureSchemes()
                ? "signatures = not reported by this JDK (classical, observed from ClientHello)"
                : hasPostQuantumSignatures()
                        ? "signatures = " + String.join(", ", postQuantumSignatureSchemes()) + " (present)"
                        : "signatures = none (classical only)";
        return kex + "; " + sig;
    }

    private static List<String> nonNull(String[] values) {
        return values == null ? List.of() : Arrays.asList(values);
    }

    private static String normalize(String name) {
        return name.toLowerCase().replace("_", "").replace("-", "");
    }
}
