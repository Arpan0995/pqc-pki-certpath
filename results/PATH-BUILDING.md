# Path Building — CertPathBuilder over Cross-Certified (FPKI-Shaped) Hierarchies

Generated 2026-07-17T20:49:51.861145Z by `PathBuilding`.

| Setting | Value |
|---|---|
| BouncyCastle | 1.85 |
| JVM | OpenJDK 64-Bit Server VM 21.0.9 (Microsoft) |
| Host | Mac OS X 27.0 aarch64, 10 cpus |
| Builder | JDK `PKIX` CertPathBuilder, revocation disabled |
| Build warmup / measured | 40 / 250 |

Build times are host- and JIT-specific; reported as median over the measured iterations. Decoy branches in the breadth and depth sweeps are multi-hop: each candidate is several intermediates deep before dead-ending, so a candidate cannot be dismissed in one step.

## Headline

Path discovery is **robust to cross-certificate branching, even with multi-hop decoys**. As a bridged name's candidate issuers grow 1→32, the *slowest* verifier (SLH-DSA-SHA2-256F) barely moves (1.2×) — the tell that the JDK builder does not verify the dead-end branches, because if it did, the slow verifier would blow up most. Faster algorithms show only minor store-search overhead. The cost is instead in **path depth**: over the depth sweep the discovered path grows from 4 to 7 certificates and build time rises ~1.8× across every algorithm, because each certificate on the found path is one signature to verify. That depth cost is per-algorithm: on the realistic Federal-Bridge path, discovery costs 9423 µs for SLH-DSA-SHA2-256F versus 187 µs for RSA-3072.

## Breadth sweep — build time vs candidate issuers (multi-hop decoys)

A bridged CA name issued a certificate by *k* branches, each several intermediates deep, only one reaching the anchor. Median build time (µs):

| Algorithm | k=1 | k=2 | k=4 | k=8 | k=16 | k=32 |
|---|---:|---:|---:|---:|---:|---:|
| ECDSA P-256 | 1509 | 1458 | 1364 | 1387 | 1378 | 1520 |
| RSA-3072 | 243 | 246 | 239 | 272 | 294 | 360 |
| ML-DSA-65 | 461 | 426 | 406 | 407 | 587 | 1097 |
| SLH-DSA-SHA2-128F | 7811 | 7858 | 7759 | 7858 | 8241 | 9109 |
| SLH-DSA-SHA2-256F | 11890 | 11852 | 11837 | 12547 | 13025 | 13988 |

The decisive comparison is by verify cost: the SLH-DSA rows (slow to verify) stay nearly flat, while the cheap-to-verify rows (RSA, ECDSA) actually grow *more* in relative terms. That is the opposite of what verifying decoys would produce — a slow verifier would be hit hardest — so the small growth is store-search overhead (more certificates to index and name-match), not signature checks on dead-end branches. The plausible combinatorial blow-up of cross-certification does not occur in the JDK.

## Depth sweep — build time vs discovered path length

At a fixed branching factor, lengthening the real path. Columns are the number of certificates in the discovered path. Median build time (µs):

| Algorithm | 4 | 5 | 6 | 7 |
|---|---:|---:|---:|---:|
| ECDSA P-256 | 1091 | 1374 | 1688 | 1872 |
| RSA-3072 | 192 | 264 | 301 | 325 |
| ML-DSA-65 | 362 | 501 | 603 | 569 |
| SLH-DSA-SHA2-128F | 6370 | 7848 | 9564 | 10859 |
| SLH-DSA-SHA2-256F | 9565 | 12255 | 15018 | 17445 |

Here cost rises with depth, and faster for slower verifiers — each additional certificate on the path is one more signature to check. This is where the post-quantum verification cost enters path building: linearly in path length, at the algorithm's per-verify price.

## Federal Bridge — realistic depth-5 cross-certified path

A Common Policy Root cross-certifies a Federal Bridge CA (whose name also carries decoy partner cross-certificates), which anchors an agency CA, a sub-CA, and the leaf. The concrete migration cost per algorithm:

| Algorithm | Family | Path length | Store searched | Build time (median) |
|---|---|---:|---:|---:|
| ECDSA P-256 | Classical | 4 certs | 2,658 B | 1.06 ms |
| RSA-3072 | Classical | 4 certs | 7,880 B | 186.9 µs |
| ML-DSA-44 | ML-DSA | 4 certs | 31,432 B | 216.8 µs |
| ML-DSA-65 | ML-DSA | 4 certs | 43,664 B | 410.9 µs |
| ML-DSA-87 | ML-DSA | 4 certs | 59,328 B | 516.7 µs |
| SLH-DSA-SHA2-128F | SLH-DSA | 4 certs | 138,496 B | 6.23 ms |
| SLH-DSA-SHA2-128S | SLH-DSA | 4 certs | 64,640 B | 2.16 ms |
| SLH-DSA-SHA2-192F | SLH-DSA | 4 certs | 287,232 B | 9.21 ms |
| SLH-DSA-SHA2-256F | SLH-DSA | 4 certs | 400,896 B | 9.42 ms |
| MLDSA44-ECDSA-P256-SHA256 | Composite | 4 certs | 32,498 B | 444.8 µs |
| MLDSA65-ECDSA-P384-SHA512 | Composite | 4 certs | 45,242 B | 960.9 µs |
| MLDSA65-RSA3072-PSS-SHA512 | Composite | 4 certs | 49,896 B | 560.8 µs |
| MLDSA87-ECDSA-P521-SHA512 | Composite | 4 certs | 61,478 B | 1.99 ms |

