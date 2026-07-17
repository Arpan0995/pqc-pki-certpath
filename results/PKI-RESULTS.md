# PQC at the PKI Layer — Chain Sizes and CertPath Validation Cost

Generated 2026-07-17T18:27:23.964846Z by `Benchmark`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| Host | Mac OS X 27.0 aarch64, 10 cpus |
| PKIX validator | SUN (JDK), signatures via BouncyCastle |
| Key-generation seed | `20260717` |
| Validation warmup / measured | 200 / 2000 iterations |

Certificate sizes are deterministic per parameter set and are host-independent. Validation times are host- and JIT-specific — reported as median and inter-quartile range over the measured iterations, on the host above.

## Headline

At the primary 3-tier depth, a transmitted certificate chain grows from **653 bytes** (ECDSA P-256) to **100,213 bytes** (SLH-DSA-SHA2-256F) — a **153×** increase. 3 algorithm(s) produce a single certificate larger than one TLS record (16,384 B).

## Chain sizes (3-tier: root → intermediate → leaf)

Transmitted chain = leaf + intermediate (the root is a trust anchor, never sent).

| Algorithm | Family | Transmitted chain | × ECDSA P-256 | Full hierarchy |
|---|---|---:|---:|---:|
| ECDSA P-256 | Classical | 653 B | 1.0× | 966 B |
| RSA-3072 | Classical | 1,959 B | 3.0× | 2,925 B |
| ML-DSA-44 | ML-DSA | 7,847 B | 12.0× | 11,757 B |
| ML-DSA-65 | ML-DSA | 10,905 B | 16.7× | 16,344 B |
| ML-DSA-87 | ML-DSA | 14,821 B | 22.7× | 22,218 B |
| SLH-DSA-SHA2-128F | SLH-DSA | 34,613 B | 53.0× | 51,906 B |
| SLH-DSA-SHA2-128S | SLH-DSA | 16,149 B | 24.7× | 24,210 B |
| SLH-DSA-SHA2-192F | SLH-DSA | 71,797 B | 109.9× | 107,682 B |
| SLH-DSA-SHA2-256F | SLH-DSA | 100,213 B | 153.5× | 150,306 B |
| MLDSA44-ECDSA-P256-SHA256 | Composite | 8,112 B | 12.4× | 12,154 B |
| MLDSA65-ECDSA-P384-SHA512 | Composite | 11,300 B | 17.3× | 16,936 B |
| MLDSA65-RSA3072-PSS-SHA512 | Composite | 12,463 B | 19.1× | 18,681 B |
| MLDSA87-ECDSA-P521-SHA512 | Composite | 15,356 B | 23.5× | 23,021 B |

## Size-threshold crossings (3-tier)

| Algorithm | Single cert | Transmitted chain | TLS record (16K) | JDK max handshake message (32K) |
|---|---:|---:|---|---|
| ECDSA P-256 | 330 B | 653 B | ok | ok |
| RSA-3072 | 983 B | 1,959 B | ok | ok |
| ML-DSA-44 | 3,927 B | 7,847 B | ok | ok |
| ML-DSA-65 | 5,456 B | 10,905 B | ok | ok |
| ML-DSA-87 | 7,414 B | 14,821 B | ok | ok |
| SLH-DSA-SHA2-128F | 17,310 B | 34,613 B | **crosses** | **crosses** |
| SLH-DSA-SHA2-128S | 8,078 B | 16,149 B | ok | ok |
| SLH-DSA-SHA2-192F | 35,902 B | 71,797 B | **crosses** | **crosses** |
| SLH-DSA-SHA2-256F | 50,110 B | 100,213 B | **crosses** | **crosses** |
| MLDSA44-ECDSA-P256-SHA256 | 4,060 B | 8,112 B | ok | ok |
| MLDSA65-ECDSA-P384-SHA512 | 5,654 B | 11,300 B | ok | ok |
| MLDSA65-RSA3072-PSS-SHA512 | 6,235 B | 12,463 B | ok | ok |
| MLDSA87-ECDSA-P521-SHA512 | 7,681 B | 15,356 B | ok | ok |

- **TLS record** (16,384 B): RFC 8446 §5.1 plaintext record limit (2^14). A larger Certificate message is fragmented across records; buffers and middleboxes sometimes assume a message fits one record.
- **JDK max handshake message** (32,768 B): jdk.tls.maxHandshakeMessageSize default. A Certificate message above this is rejected by the JDK TLS stack unless the property is raised.

## Certificate size decomposition (single leaf certificate)

Where the bytes go: public key vs signature vs fixed X.509 overhead. This is what separates ML-DSA (large key *and* signature) from SLH-DSA (tiny key, dominant signature).

| Algorithm | Total | Public key | Signature | Overhead | Signature share |
|---|---:|---:|---:|---:|---:|
| ECDSA P-256 | 330 B | 91 B | 71 B | 168 B | 22% |
| RSA-3072 | 983 B | 422 B | 384 B | 177 B | 39% |
| ML-DSA-44 | 3,927 B | 1,334 B | 2,420 B | 173 B | 62% |
| ML-DSA-65 | 5,456 B | 1,974 B | 3,309 B | 173 B | 61% |
| ML-DSA-87 | 7,414 B | 2,614 B | 4,627 B | 173 B | 62% |
| SLH-DSA-SHA2-128F | 17,310 B | 50 B | 17,088 B | 172 B | 99% |
| SLH-DSA-SHA2-128S | 8,078 B | 50 B | 7,856 B | 172 B | 97% |
| SLH-DSA-SHA2-192F | 35,902 B | 66 B | 35,664 B | 172 B | 99% |
| SLH-DSA-SHA2-256F | 50,110 B | 82 B | 49,856 B | 172 B | 99% |
| MLDSA44-ECDSA-P256-SHA256 | 4,060 B | 1,398 B | 2,491 B | 171 B | 61% |
| MLDSA65-ECDSA-P384-SHA512 | 5,654 B | 2,070 B | 3,413 B | 171 B | 60% |
| MLDSA65-RSA3072-PSS-SHA512 | 6,235 B | 2,371 B | 3,693 B | 171 B | 59% |
| MLDSA87-ECDSA-P521-SHA512 | 7,681 B | 2,746 B | 4,764 B | 171 B | 62% |

## Path-validation timing (3-tier)

Median per-validation time with the inter-quartile range; the JDK PKIX validator, revocation disabled. Host- and JIT-specific.

| Algorithm | Median | IQR | × ECDSA P-256 |
|---|---:|---:|---:|
| ECDSA P-256 | 543.3 µs | 28.8 µs | 1.00× |
| RSA-3072 | 94.2 µs | 2.5 µs | 0.17× |
| ML-DSA-44 | 109.0 µs | 7.9 µs | 0.20× |
| ML-DSA-65 | 158.8 µs | 3.2 µs | 0.29× |
| ML-DSA-87 | 259.5 µs | 10.4 µs | 0.48× |
| SLH-DSA-SHA2-128F | 3.18 ms | 116.1 µs | 5.85× |
| SLH-DSA-SHA2-128S | 1.12 ms | 65.4 µs | 2.06× |
| SLH-DSA-SHA2-192F | 4.88 ms | 177.5 µs | 8.99× |
| SLH-DSA-SHA2-256F | 4.94 ms | 148.3 µs | 9.08× |
| MLDSA44-ECDSA-P256-SHA256 | 216.8 µs | 7.5 µs | 0.40× |
| MLDSA65-ECDSA-P384-SHA512 | 466.6 µs | 14.1 µs | 0.86× |
| MLDSA65-RSA3072-PSS-SHA512 | 266.2 µs | 9.3 µs | 0.49× |
| MLDSA87-ECDSA-P521-SHA512 | 964.0 µs | 25.9 µs | 1.77× |

## Scaling with tier depth

Transmitted chain size by tier count, per algorithm — a linear rise means each added tier adds one certificate of roughly constant size.

| Algorithm | 2-tier | 3-tier | 4-tier |
|---|---:|---:|---:|
| ECDSA P-256 | 321 B | 653 B | 987 B |
| RSA-3072 | 973 B | 1,959 B | 2,945 B |
| ML-DSA-44 | 3,917 B | 7,847 B | 11,777 B |
| ML-DSA-65 | 5,446 B | 10,905 B | 16,364 B |
| ML-DSA-87 | 7,404 B | 14,821 B | 22,238 B |
| SLH-DSA-SHA2-128F | 17,300 B | 34,613 B | 51,926 B |
| SLH-DSA-SHA2-128S | 8,068 B | 16,149 B | 24,230 B |
| SLH-DSA-SHA2-192F | 35,892 B | 71,797 B | 107,702 B |
| SLH-DSA-SHA2-256F | 50,100 B | 100,213 B | 150,326 B |
| MLDSA44-ECDSA-P256-SHA256 | 4,050 B | 8,112 B | 12,177 B |
| MLDSA65-ECDSA-P384-SHA512 | 5,644 B | 11,300 B | 16,954 B |
| MLDSA65-RSA3072-PSS-SHA512 | 6,225 B | 12,463 B | 18,701 B |
| MLDSA87-ECDSA-P521-SHA512 | 7,673 B | 15,356 B | 23,042 B |

## Pre-registered hypotheses

Fixed in the design before data collection (§4), scored mechanically from the numbers above.

| | Verdict | Evidence |
|---|---|---|
| **H1** | supported | largest PQC chain is 153.5× the classical baseline (100213 vs 653 B); SLH-DSA 'f' cert > 16,384 B: true; SLH-DSA 'f' 3-tier chain > 32,768 B: true. |
| **H2** | not supported | ML-DSA-65 validation is 1.7× classical (threshold ≤ 5×); across PQC, the worst size penalty is 51× vs the worst time penalty 52.4× — size exceeds CPU by 1.0× (threshold ≥ 5×). |
| **H3** | supported | MLDSA65-ECDSA-P384 chain is 1.04× the pure ML-DSA-65 chain (11300 vs 10905 B); supported when between 1.0× and 1.5×. |
| **H4** | supported | ML-DSA-65 transmitted bytes 2/3/4 tiers = 5446/10905/16364; ratios to 2-tier are 2.00 and 3.00 (linear predicts 2.00 and 3.00, ±0.15). |

- **H1** — PQC chains are at least an order of magnitude larger than classical; every SLH-DSA 'f' certificate exceeds one TLS record (16,384 B); a 3-tier SLH-DSA 'f' chain exceeds the JDK max handshake message (32,768 B).
- **H2** — ML-DSA path validation is within a small factor of classical, and the relative size penalty of PQC dwarfs its relative validation-time penalty: the PKI-layer cost is bytes, not CPU.
- **H3** — A composite (PQC + classical) chain costs its ML-DSA component plus a modest classical increment — closer to pure ML-DSA than to double it.
- **H4** — Total chain size scales linearly with tier depth: each added tier adds one more transmitted certificate of roughly constant size.

