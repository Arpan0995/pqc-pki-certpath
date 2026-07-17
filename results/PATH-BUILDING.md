# Path Building — CertPathBuilder over Cross-Certified (FPKI-Shaped) Hierarchies

Generated 2026-07-17T19:45:59.411654Z by `PathBuilding`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| Host | Mac OS X 27.0 aarch64, 10 cpus |
| Builder | JDK `PKIX` CertPathBuilder, revocation disabled |
| Build warmup / measured | 100 / 1000 |

Build times are host- and JIT-specific; reported as median over the measured iterations.

## Headline

Path discovery is **robust to cross-certificate branching**: growing a bridged name from 1 to 32 candidate issuers barely moves build time (worst case SLH-DSA-SHA2-128F, 1.0×). The JDK builder prunes candidates by name and trust-anchor priority before verifying signatures, so branching does not amplify cost even for a slow verifier like SLH-DSA — a reassuring result for cross-certified FPKI. On the realistic Federal-Bridge path, discovery costs 9984 µs for SLH-DSA-SHA2-256F versus 188 µs for RSA-3072 — the post-quantum signature cost carries into path building, not just validation.

## Branching sweep — build time vs candidate issuers

A single bridged CA name issued a certificate by *k* different roots, only one of which chains to the trust anchor. Median path-build time (µs):

| Algorithm | k=1 | k=2 | k=4 | k=8 | k=16 | k=32 |
|---|---:|---:|---:|---:|---:|---:|
| ECDSA P-256 | 575.4 | 558.4 | 536.3 | 538.0 | 532.5 | 537.8 |
| RSA-3072 | 102.1 | 94.7 | 97.3 | 94.7 | 96.3 | 103.9 |
| ML-DSA-65 | 167.7 | 162.0 | 162.5 | 164.5 | 166.1 | 173.4 |
| SLH-DSA-SHA2-128F | 3118.2 | 3221.3 | 3139.2 | 3216.2 | 3134.0 | 3251.2 |
| SLH-DSA-SHA2-256F | 4931.8 | 5090.9 | 4938.0 | 5003.1 | 5066.0 | 5122.4 |

If build time is flat in *k*, the builder prunes candidates by name before verifying signatures, and post-quantum cost does not amplify discovery. If it rises with *k*, the builder verifies candidates it later discards, and each wasted verification costs the algorithm's full signature-check price — which is where a slow verifier like SLH-DSA would stand out.

## Federal Bridge — realistic depth-5 cross-certified path

A Common Policy Root cross-certifies a Federal Bridge CA (whose name also carries decoy partner cross-certificates), which anchors an agency CA, a sub-CA, and the leaf. The concrete migration cost per algorithm:

| Algorithm | Family | Path length | Store searched | Build time (median) |
|---|---|---:|---:|---:|
| ECDSA P-256 | Classical | 4 certs | 2,653 B | 1.06 ms |
| RSA-3072 | Classical | 4 certs | 7,880 B | 187.9 µs |
| ML-DSA-44 | ML-DSA | 4 certs | 31,432 B | 211.0 µs |
| ML-DSA-65 | ML-DSA | 4 certs | 43,664 B | 331.7 µs |
| ML-DSA-87 | ML-DSA | 4 certs | 59,328 B | 525.7 µs |
| SLH-DSA-SHA2-128F | SLH-DSA | 4 certs | 138,496 B | 6.61 ms |
| SLH-DSA-SHA2-128S | SLH-DSA | 4 certs | 64,640 B | 2.30 ms |
| SLH-DSA-SHA2-192F | SLH-DSA | 4 certs | 287,232 B | 9.77 ms |
| SLH-DSA-SHA2-256F | SLH-DSA | 4 certs | 400,896 B | 9.98 ms |
| MLDSA44-ECDSA-P256-SHA256 | Composite | 4 certs | 32,497 B | 448.0 µs |
| MLDSA65-ECDSA-P384-SHA512 | Composite | 4 certs | 45,242 B | 948.7 µs |
| MLDSA65-RSA3072-PSS-SHA512 | Composite | 4 certs | 49,896 B | 533.5 µs |
| MLDSA87-ECDSA-P521-SHA512 | Composite | 4 certs | 61,476 B | 1.95 ms |

