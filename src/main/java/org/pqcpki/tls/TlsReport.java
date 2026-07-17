package org.pqcpki.tls;

import org.pqcpki.env.Environment;

import java.time.Instant;
import java.util.List;
import java.util.Locale;

/** Renders the TLS readiness experiment as Markdown (design §13). */
public final class TlsReport {

    private static final int SIZE_LIMIT = 32_768;

    private TlsReport() {
    }

    public static String render(List<TlsReadiness.AuthRow> auth, List<TlsReadiness.SizeRow> size) {
        StringBuilder out = new StringBuilder();
        out.append("# TLS Readiness — Can Java Authenticate with Post-Quantum Certificates?\n\n");
        appendProvenance(out);
        appendHeadline(out, auth, size);
        appendAuth(out, auth);
        appendSize(out, size);
        return out.toString();
    }

    private static void appendProvenance(StringBuilder out) {
        out.append("Generated ").append(Instant.now()).append(" by `TlsReadiness`.\n\n");
        out.append("| Setting | Value |\n|---|---|\n");
        out.append("| BouncyCastle | ").append(Environment.bouncyCastleVersion()).append(" |\n");
        out.append("| JVM | ").append(Environment.jvm()).append(" |\n");
        out.append("| Host | ").append(Environment.host()).append(" |\n");
        out.append("| TLS | 1.3, loopback, endpoint identification and revocation disabled |\n");
        out.append("| `jdk.tls.maxHandshakeMessageSize` | ")
                .append(System.getProperty("jdk.tls.maxHandshakeMessageSize", "default (32768)"))
                .append(" |\n");
        out.append("| JSSE PQC support (this JDK) | ")
                .append(JsseCapabilities.ofDefaultProvider().summary()).append(" |\n\n");
    }

    private static void appendHeadline(StringBuilder out, List<TlsReadiness.AuthRow> auth,
                                       List<TlsReadiness.SizeRow> size) {
        long pqcTotal = auth.stream().filter(r -> !r.algorithm().isClassical()).count();
        long pqcOk = auth.stream()
                .filter(r -> !r.algorithm().isClassical() && r.outcome().succeeded()).count();
        long classicalOk = auth.stream()
                .filter(r -> r.algorithm().isClassical() && r.outcome().succeeded()).count();
        long classicalTotal = auth.stream().filter(r -> r.algorithm().isClassical()).count();

        out.append("## Headline\n\n");
        out.append(String.format(Locale.ROOT,
                "**Post-quantum certificate authentication does not work on Java's TLS stack yet.** "
                        + "Across both JSSE providers, %d of %d post-quantum handshake attempts "
                        + "succeeded; the classical controls succeeded %d of %d. ",
                pqcOk, pqcTotal, classicalOk, classicalTotal));

        TlsReadiness.SizeRow firstBreak = size.stream()
                .filter(r -> r.outcome().category() == HandshakeOutcome.Category.SIZE_LIMIT)
                .findFirst().orElse(null);
        if (firstBreak != null) {
            out.append(String.format(Locale.ROOT,
                    "Separately, on the size axis (holding the algorithm classical so authentication "
                            + "succeeds), a chain the size of a real %s chain (~%,d B) is the smallest "
                            + "tested that crosses `jdk.tls.maxHandshakeMessageSize` (%,d B) and fails "
                            + "before validation.",
                    firstBreak.algorithm().displayName(), firstBreak.targetBytes(), SIZE_LIMIT));
        }
        out.append("\n\nThe two failures are independent: PQC certificates fail on **authentication** "
                + "regardless of size, and large chains fail on **size** regardless of algorithm. A "
                + "post-quantum deployment meets the first wall today and the second the moment the "
                + "first is removed.\n\n");
    }

    private static void appendAuth(StringBuilder out, List<TlsReadiness.AuthRow> auth) {
        out.append("## Experiment 1 — Authentication\n\n");
        out.append("A real TLS 1.3 handshake with a leaf certificate signed by each algorithm. The "
                + "question is whether the provider can negotiate the leaf's signature scheme.\n\n");
        out.append("| Algorithm | Family | SunJSSE | BCJSSE |\n|---|---|---|---|\n");
        List<String> ids = auth.stream().map(r -> r.algorithm().id()).distinct().toList();
        for (String id : ids) {
            List<TlsReadiness.AuthRow> rows = auth.stream()
                    .filter(r -> r.algorithm().id().equals(id)).toList();
            var spec = rows.get(0).algorithm();
            out.append("| ").append(spec.displayName())
                    .append(" | ").append(spec.family().category())
                    .append(" | ").append(cell(rows, "SunJSSE"))
                    .append(" | ").append(cell(rows, "BCJSSE"))
                    .append(" |\n");
        }
        out.append("\nClassical algorithms authenticate on both providers. Every ML-DSA, SLH-DSA and "
                + "composite algorithm fails with a handshake failure: the JSSE providers advertise only "
                + "classical `signature_algorithms`, so a server holding a post-quantum leaf has no "
                + "scheme to negotiate. The TLS 1.3 signature-scheme codepoints for these algorithms are "
                + "still IETF drafts and are unimplemented here.\n\n");
    }

    private static void appendSize(StringBuilder out, List<TlsReadiness.SizeRow> size) {
        out.append("## Experiment 2 — Size limit\n\n");
        out.append("ECDSA certificates (which authenticate) grown to the measured size of each "
                + "algorithm's real 3-tier chain, so any failure is size alone. The server sends leaf + "
                + "intermediate.\n\n");
        out.append("| Chain sized like | ~Transmitted bytes | Handshake |\n|---|---:|---|\n");
        for (TlsReadiness.SizeRow r : size) {
            out.append("| ").append(r.algorithm().displayName())
                    .append(" | ").append(String.format(Locale.ROOT, "%,d B", r.targetBytes()))
                    .append(" | ").append(describe(r.outcome()))
                    .append(" |\n");
        }
        out.append("\nThe threshold is `jdk.tls.maxHandshakeMessageSize` (default ")
                .append(String.format(Locale.ROOT, "%,d", SIZE_LIMIT))
                .append(" B). Chains at or below it complete; larger ones are rejected with "
                        + "`SSLProtocolException: ... exceeds the maximum allowed size`. Raising the "
                        + "property admits larger chains, so this is a configuration ceiling, not a hard "
                        + "cryptographic limit — but it is the out-of-the-box default a deployment "
                        + "meets first.\n\n");
    }

    private static String cell(List<TlsReadiness.AuthRow> rows, String provider) {
        return rows.stream().filter(r -> r.provider().equals(provider)).findFirst()
                .map(r -> r.outcome().succeeded() ? "authenticates"
                        : "**" + shortCategory(r.outcome()) + "**")
                .orElse("—");
    }

    private static String describe(HandshakeOutcome outcome) {
        if (outcome.succeeded()) {
            return "completes";
        }
        return "**" + shortCategory(outcome) + "**";
    }

    private static String shortCategory(HandshakeOutcome outcome) {
        return switch (outcome.category()) {
            case SUCCESS -> "ok";
            case AUTH_FAILURE -> "auth fails";
            case SIZE_LIMIT -> "size limit";
            case OTHER_FAILURE -> "fails";
        };
    }
}
