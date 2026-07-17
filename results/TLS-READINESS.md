# TLS Readiness — Can Java Authenticate with Post-Quantum Certificates?

Generated 2026-07-17T19:43:27.884761Z by `TlsReadiness`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| Host | Mac OS X 27.0 aarch64, 10 cpus |
| TLS | 1.3, loopback, endpoint identification and revocation disabled |
| `jdk.tls.maxHandshakeMessageSize` | default (32768) |

## Headline

**Post-quantum certificate authentication does not work on Java's TLS stack yet.** Across both JSSE providers, 0 of 22 post-quantum handshake attempts succeeded; the classical controls succeeded 4 of 4. Separately, on the size axis (holding the algorithm classical so authentication succeeds), a chain the size of a real SLH-DSA-SHA2-128F chain (~34,574 B) is the smallest tested that crosses `jdk.tls.maxHandshakeMessageSize` (32,768 B) and fails before validation.

The two failures are independent: PQC certificates fail on **authentication** regardless of size, and large chains fail on **size** regardless of algorithm. A post-quantum deployment meets the first wall today and the second the moment the first is removed.

## Experiment 1 — Authentication

A real TLS 1.3 handshake with a leaf certificate signed by each algorithm. The question is whether the provider can negotiate the leaf's signature scheme.

| Algorithm | Family | SunJSSE | BCJSSE |
|---|---|---|---|
| ECDSA P-256 | Classical | authenticates | authenticates |
| RSA-3072 | Classical | authenticates | authenticates |
| ML-DSA-44 | ML-DSA | **auth fails** | **auth fails** |
| ML-DSA-65 | ML-DSA | **auth fails** | **auth fails** |
| ML-DSA-87 | ML-DSA | **auth fails** | **auth fails** |
| SLH-DSA-SHA2-128F | SLH-DSA | **auth fails** | **auth fails** |
| SLH-DSA-SHA2-128S | SLH-DSA | **auth fails** | **auth fails** |
| SLH-DSA-SHA2-192F | SLH-DSA | **auth fails** | **auth fails** |
| SLH-DSA-SHA2-256F | SLH-DSA | **auth fails** | **auth fails** |
| MLDSA44-ECDSA-P256-SHA256 | Composite | **auth fails** | **auth fails** |
| MLDSA65-ECDSA-P384-SHA512 | Composite | **auth fails** | **auth fails** |
| MLDSA65-RSA3072-PSS-SHA512 | Composite | **auth fails** | **auth fails** |
| MLDSA87-ECDSA-P521-SHA512 | Composite | **auth fails** | **auth fails** |

Classical algorithms authenticate on both providers. Every ML-DSA, SLH-DSA and composite algorithm fails with a handshake failure: the JSSE providers advertise only classical `signature_algorithms`, so a server holding a post-quantum leaf has no scheme to negotiate. The TLS 1.3 signature-scheme codepoints for these algorithms are still IETF drafts and are unimplemented here.

## Experiment 2 — Size limit

ECDSA certificates (which authenticate) grown to the measured size of each algorithm's real 3-tier chain, so any failure is size alone. The server sends leaf + intermediate.

| Chain sized like | ~Transmitted bytes | Handshake |
|---|---:|---|
| ECDSA P-256 | 707 B | completes |
| RSA-3072 | 1,919 B | completes |
| ML-DSA-44 | 7,806 B | completes |
| ML-DSA-65 | 10,865 B | completes |
| ML-DSA-87 | 14,781 B | completes |
| SLH-DSA-SHA2-128F | 34,574 B | **size limit** |
| SLH-DSA-SHA2-128S | 16,110 B | completes |
| SLH-DSA-SHA2-192F | 71,756 B | **size limit** |
| SLH-DSA-SHA2-256F | 100,174 B | **size limit** |
| MLDSA44-ECDSA-P256-SHA256 | 8,072 B | completes |
| MLDSA65-ECDSA-P384-SHA512 | 11,260 B | completes |
| MLDSA65-RSA3072-PSS-SHA512 | 12,424 B | completes |
| MLDSA87-ECDSA-P521-SHA512 | 15,315 B | completes |

The threshold is `jdk.tls.maxHandshakeMessageSize` (default 32,768 B). Chains at or below it complete; larger ones are rejected with `SSLProtocolException: ... exceeds the maximum allowed size`. Raising the property admits larger chains, so this is a configuration ceiling, not a hard cryptographic limit — but it is the out-of-the-box default a deployment meets first.

