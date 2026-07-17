# pqc-pki-certpath

**Certificates, not handshakes.** A Java measurement of what post-quantum cryptography costs at the
X.509 **PKI layer** — certificate chain sizes and `CertPath` validation time — rather than at the TLS
handshake, where almost all PQC measurement has focused.

Every certificate in a chain carries a signature, and a real chain has several: a leaf signed by an
intermediate, signed by a root. A classical ECDSA chain is a few hundred bytes; the same chain with
SLH-DSA signatures is tens of kilobytes. This project generates multi-tier PQC, classical, and composite
X.509 hierarchies with BouncyCastle and measures, for each, how large the chain gets and how long the
JDK's `PKIX` validator takes to validate it.

## Status

Harness built and validated; benchmark run. 13 algorithms × 3 tier depths, results in
[`results/`](results/). The pre-registered design — research questions, algorithm set, size thresholds,
and hypotheses — is in [`docs/EXPERIMENT-DESIGN.md`](docs/EXPERIMENT-DESIGN.md); **read that first.**

## The headline: for ML-DSA the cost is bytes not CPU — but SLH-DSA costs both

The usual PQC narrative is about compute. At the PKI/validation layer, that framing is right for one
family and wrong for the other, and the split is the finding (measured on JDK 21 + BouncyCastle 1.85):

- **ML-DSA — bytes, not CPU.** Path validation only *verifies*, and ML-DSA verification is genuinely
  cheap: a 3-tier ML-DSA-65 chain validates in ~160 µs, *faster* than the same ECDSA P-256 chain
  (~530 µs) and within ~2× of RSA-3072, while being ~17× the size. For ML-DSA, the migration cost is
  purely the extra bytes.
- **SLH-DSA — bytes *and* CPU.** Its signatures are enormous *and* its verification is milliseconds:
  1–5 ms per validation, up to ~55× the RSA-3072 baseline. For the high-security fast variants the
  relative CPU penalty actually *rivals* the (already order-of-magnitude) size penalty — so the tidy
  "PQC verification is free" story does not survive contact with SLH-DSA-256F.

This nuance is why the pre-registered hypothesis H2 ("the PKI-layer cost is bytes, not CPU") comes back
**not supported** in general: it holds cleanly for ML-DSA and is refuted by SLH-DSA. Pre-registering it
is what made the distinction visible rather than glossed over. See
[`results/FINDINGS.md`](results/FINDINGS.md).

On size, the story is uniform and dramatic:

- A 3-tier chain grows from ~650 bytes (ECDSA P-256) to ~11 KB (ML-DSA-65) to ~35 KB (SLH-DSA-SHA2-128F)
  to ~100 KB (SLH-DSA-SHA2-256F) — up to ~150× classical.
- A single SLH-DSA-SHA2-128F certificate (~17 KB) exceeds one TLS record (16,384 B); a 3-tier chain of
  it (~35 KB) exceeds the JDK's default maximum handshake message size (32,768 B).
- Where the bytes go differs sharply by family: an ML-DSA certificate splits its size between a large
  public key and a large signature (~60% signature); an SLH-DSA certificate is almost *all* signature
  (~99%) over a 32-byte key. This changes what is worth caching or reusing.

The exact figures, threshold crossings, and per-hypothesis verdicts are regenerated into
[`results/PKI-RESULTS.md`](results/PKI-RESULTS.md) and [`results/pki-results.csv`](results/pki-results.csv).

## Part II: from threshold arithmetic to demonstrated breakage

Part I compared measured sizes to documented limits and validated chains already in hand. Part II closes
those gaps with real handshakes and real path discovery. Two findings, in
[`results/TLS-READINESS.md`](results/TLS-READINESS.md), [`results/PATH-BUILDING.md`](results/PATH-BUILDING.md),
and [`results/FINDINGS.md`](results/FINDINGS.md):

- **Java can't authenticate with PQC certificates at all yet — before size is even the problem.** Driving
  real TLS 1.3 handshakes, *every* ML-DSA/SLH-DSA/composite leaf fails on **both** JSSE providers
  (`SunJSSE` and BouncyCastle's `BCJSSE`) with `handshake_failure`; classical controls pass. The cause is
  authentication, not size: JSSE advertises only classical `signature_algorithms` (the PQC TLS 1.3
  codepoints are still IETF drafts). And when a chain is grown to real PQC sizes with classical signatures,
  the SLH-DSA-`f`-sized chains (~34 KB+) fail with `SSLProtocolException: ... exceeds the maximum allowed
  size (32768)` — the two walls a deployment hits, in order.
- **Path building is robust to cross-cert branching, but inherits the PQC verify cost with depth.** Over
  Federal-Bridge-shaped cross-certified stores — with **multi-hop decoy branches** that can't be pruned
  in one step — `CertPathBuilder` discovery time stays flat as a bridged name's candidate-issuer count
  grows 1→32. The tell is that the *slowest* verifier (SLH-DSA) is the *least* amplified, so the builder
  isn't verifying dead ends (reassuring for FPKI). The cost is instead in path depth: a realistic depth-5
  bridged path costs ~9 ms to discover for SLH-DSA-256F vs ~0.2 ms for RSA-3072 — the "bytes *and* CPU"
  cost of SLH-DSA, at the discovery layer. (A third JDK ceiling also appears: the default PKIX
  `maxPathLength` of 5 rejects deeper cross-certified paths outright.)

## What is measured

For each algorithm and tier depth (2/3/4 = root→leaf, root→intermediate→leaf, and one deeper):

- **Chain size** — the transmitted chain (leaf + intermediates; the root is a trust anchor, never sent),
  and the full hierarchy.
- **Size decomposition** — each certificate split into public key / signature / fixed X.509 overhead.
- **Validation time** — the JDK's own `PKIX` `CertPathValidator`, warmed up and repeated, reported as
  median and inter-quartile range (timing is skewed, so not the mean).
- **Threshold crossings** — measured chain size against the TLS record limit and the JDK handshake
  message limit.

The JDK validator is used deliberately: it is what a standard Java application uses, and it validates
PQC and composite chains by delegating each signature verification to the registered BouncyCastle
provider.

## Algorithms

| Family | Members |
|---|---|
| Classical (baseline) | ECDSA P-256, RSA-3072 |
| ML-DSA (FIPS 204) | ML-DSA-44, ML-DSA-65, ML-DSA-87 |
| SLH-DSA (FIPS 205) | SHA2-128f, SHA2-128s, SHA2-192f, SHA2-256f |
| Composite (IETF LAMPS) | MLDSA44-ECDSA-P256, MLDSA65-ECDSA-P384, MLDSA65-RSA3072-PSS, MLDSA87-ECDSA-P521 |

Every certificate uses one fixed profile (validity, DN structure, BasicConstraints + KeyUsage), so all
differences are attributable to the cryptography, not to certificate content.

## Running

```bash
mvn test                       # unit tests: builds and PKIX-validates every algorithm

mvn package                    # build the shaded jar (Part I sizes + validation)
java -jar target/pqc-pki.jar   # full benchmark: all algorithms × tiers 2,3,4 -> results/PKI-RESULTS.md

# Part II (run from the classpath; each writes its own report into results/)
mvn -q dependency:build-classpath -Dmdep.outputFile=cp.txt
java -cp target/classes:$(cat cp.txt) org.pqcpki.tls.TlsReadiness    # -> results/TLS-READINESS.md
java -cp target/classes:$(cat cp.txt) org.pqcpki.build.PathBuilding  # -> results/PATH-BUILDING.md
```

`Benchmark` options: `--algorithms=a,b`, `--tiers=2,3,4`, `--seed=N`, `--warmup=N`, `--iterations=N`,
`--out=DIR`, `--no-timing` (sizes only). Certificate sizes are deterministic and host-independent;
validation, handshake, and path-build times are host-specific, so re-run locally for timing figures on
your hardware.

## Toolchain

Java 21 (pinned OpenJDK 21); BouncyCastle `bcprov-jdk18on` + `bcpkix-jdk18on` 1.85; Maven. Certificate
sizes are exact and reproducible from the key-generation seed; validation timing is reported on the host
recorded in each results file.

## Layout

```
docs/EXPERIMENT-DESIGN.md   Pre-registered design + Part II (read this first)
src/main/java/org/pqcpki/
  algo/        The algorithm registry (classical, ML-DSA, SLH-DSA, composite)
  pki/         Key generation, X.509 issuance, multi-tier hierarchy construction
  measure/     Size decomposition, robust statistics, the validation benchmark
  validate/    The JDK PKIX path validator wrapper
  report/      Size thresholds, hypothesis scoring, Markdown + CSV output
  tls/         Part II: real TLS 1.3 handshake readiness + size-breakage experiment
  build/       Part II: cross-certified/FPKI models + CertPathBuilder path-discovery benchmark
  Benchmark.java        Part I entry point (sizes + validation)
results/       PKI-RESULTS.md + csv (Part I), TLS-READINESS.md + PATH-BUILDING.md (Part II), FINDINGS.md
```

## Sibling projects

Part of a set measuring the Java post-quantum transition: `pqc-decode-fuzzing` (parser robustness),
`pqc-jvm-sidechannel` (constant-time behaviour). This one is the PKI layer.

## License

Apache-2.0 (see `LICENSE`).
