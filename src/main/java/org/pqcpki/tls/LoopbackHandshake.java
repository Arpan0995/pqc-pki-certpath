package org.pqcpki.tls;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import java.net.InetAddress;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Drives one real TLS 1.3 handshake between a server and client on the loopback interface, and reports
 * what happened. The server presents {@code chain} authenticated by {@code leafKey}; the client trusts
 * {@code trustAnchor}.
 *
 * <p>Everything incidental is turned off so the result reflects the certificate and its size, nothing
 * else: TLS is pinned to 1.3, endpoint identification (hostname checking) is disabled, and revocation is
 * not consulted. What remains to succeed or fail is signature-scheme negotiation and the handshake
 * message size — exactly the two axes under study.
 *
 * <p>Both JSSE providers are exercised through the same code by name: {@code "SunJSSE"} (the JDK's own)
 * and {@code "BCJSSE"} (BouncyCastle's). The provider must already be registered.
 */
public final class LoopbackHandshake {

    private static final char[] PASSWORD = "pqcpki".toCharArray();
    private static final int HANDSHAKE_TIMEOUT_MS = 15_000;

    private final String jsseProvider;

    public LoopbackHandshake(String jsseProvider) {
        this.jsseProvider = jsseProvider;
    }

    /**
     * Attempt one handshake.
     *
     * @param chain       the server's certificate chain, leaf first
     * @param leafKey     the leaf's private key
     * @param trustAnchor the root the client trusts
     */
    public HandshakeOutcome attempt(List<X509Certificate> chain, PrivateKey leafKey,
                                    X509Certificate trustAnchor) {
        try {
            SSLContext context = context(chain, leafKey, trustAnchor);
            return run(context);
        } catch (Throwable t) {
            return HandshakeOutcome.failure(rootCause(t));
        }
    }

    private SSLContext context(List<X509Certificate> chain, PrivateKey leafKey,
                               X509Certificate trustAnchor) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(null, null);
        keyStore.setKeyEntry("leaf", leafKey, PASSWORD, chain.toArray(new Certificate[0]));

        KeyStore trustStore = KeyStore.getInstance("PKCS12", "BC");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("anchor", trustAnchor);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", jsseProvider);
        kmf.init(keyStore, PASSWORD);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", jsseProvider);
        tmf.init(trustStore);
        SSLContext context = SSLContext.getInstance("TLS", jsseProvider);
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context;
    }

    private HandshakeOutcome run(SSLContext context) throws Exception {
        try (SSLServerSocket server = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            server.setEnabledProtocols(new String[]{"TLSv1.3"});
            int port = server.getLocalPort();

            Throwable[] serverError = new Throwable[1];
            Thread serverThread = new Thread(() -> {
                try (SSLSocket socket = (SSLSocket) server.accept()) {
                    socket.setUseClientMode(false);
                    socket.startHandshake();
                    socket.getInputStream().read();
                } catch (Throwable t) {
                    serverError[0] = t;
                }
            }, "pqcpki-tls-server");
            serverThread.setDaemon(true);
            serverThread.start();

            try (SSLSocket client = (SSLSocket) context.getSocketFactory()
                    .createSocket("127.0.0.1", port)) {
                client.setEnabledProtocols(new String[]{"TLSv1.3"});
                SSLParameters params = client.getSSLParameters();
                params.setEndpointIdentificationAlgorithm(null);
                client.setSSLParameters(params);
                client.startHandshake();
                int chainBytes = encodedChainBytes(client);
                client.getOutputStream().write(0x2A);
                client.getOutputStream().flush();
                serverThread.join(HANDSHAKE_TIMEOUT_MS);
                return HandshakeOutcome.success(chainBytes, client.getSession().getProtocol()
                        + " / " + client.getSession().getCipherSuite());
            } catch (Throwable clientError) {
                serverThread.join(HANDSHAKE_TIMEOUT_MS);
                // Prefer the size-limit signal wherever it appears: the JDK reports it on whichever side
                // read the oversized message, which is not always the side that threw first.
                Throwable serverSide = serverError[0];
                HandshakeOutcome clientOutcome = HandshakeOutcome.failure(rootCause(clientError));
                if (clientOutcome.category() != HandshakeOutcome.Category.SIZE_LIMIT && serverSide != null) {
                    HandshakeOutcome serverOutcome = HandshakeOutcome.failure(rootCause(serverSide));
                    if (serverOutcome.category() == HandshakeOutcome.Category.SIZE_LIMIT) {
                        return serverOutcome;
                    }
                }
                return clientOutcome;
            }
        }
    }

    /** Bytes of the certificate chain the server actually sent, as seen by the client. */
    private static int encodedChainBytes(SSLSocket client) {
        try {
            int sum = 0;
            for (Certificate certificate : client.getSession().getPeerCertificates()) {
                sum += certificate.getEncoded().length;
            }
            return sum;
        } catch (Exception e) {
            return 0;
        }
    }

    private static Throwable rootCause(Throwable t) {
        Throwable cause = t;
        while (cause.getCause() != null && cause.getCause() != cause) {
            cause = cause.getCause();
        }
        return cause;
    }
}
