# Findings

Interpretation of the measured results in [`PKI-RESULTS.md`](PKI-RESULTS.md). Figures are from JDK 21 +
BouncyCastle 1.85 on the host recorded there; sizes are deterministic and host-independent, timings are
host-specific.

## 1. Size: one to two orders of magnitude, uniformly (RQ1, H1 — supported)

A 3-tier transmitted chain grows from **653 B** (ECDSA P-256) across the whole PQC range:

| | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 | SLH-DSA-128s | SLH-DSA-128f | SLH-DSA-192f | SLH-DSA-256f |
|---|---|---|---|---|---|---|---|
| 3-tier chain | 7.8 KB | 10.9 KB | 14.8 KB | 16.1 KB | 34.6 KB | 71.8 KB | 100.2 KB |
| × ECDSA P-256 | 12× | 17× | 23× | 25× | 53× | 110× | **153×** |

The heaviest option, SLH-DSA-SHA2-256F, produces a 100 KB three-certificate chain — 153× the classical
baseline. This is a bandwidth and storage cost, paid on every connection that transmits the chain and in
every store that holds it.

## 2. The cost is bytes for ML-DSA, but bytes *and* CPU for SLH-DSA (RQ2, H2 — not supported)

The pre-registered H2 predicted that the PKI-layer cost of PQC is bytes, not CPU — that path validation,
which only *verifies*, stays cheap even where signatures are huge. **This holds for ML-DSA and breaks
for SLH-DSA**, and the split is the most interesting result of the study.

| | validation (median) | × ECDSA P-256 | × RSA-3072 |
|---|---|---|---|
| ECDSA P-256 | 528 µs | 1.0× | 5.8× |
| RSA-3072 | 91 µs | 0.17× | 1.0× |
| ML-DSA-65 | 158 µs | 0.30× | 1.7× |
| ML-DSA-87 | 244 µs | 0.46× | 2.7× |
| SLH-DSA-128f | 3.08 ms | 5.8× | 34× |
| SLH-DSA-256f | 4.96 ms | 9.4× | **55×** |

- **ML-DSA validation is genuinely cheap** — faster than ECDSA P-256, and within ~2× of RSA-3072, at
  12–23× the size. For ML-DSA the migration really is a bytes-only problem.
- **SLH-DSA validation is milliseconds** — 1–5 ms, i.e. 2–9× ECDSA or up to ~55× the RSA-3072 baseline.
  For SLH-DSA-256F the relative CPU penalty (55×) actually exceeds the relative size penalty (51× vs the
  RSA-3072 chain), so the "bytes not CPU" framing inverts. SLH-DSA is expensive on *both* axes.

H2 as pre-registered was a universal claim, and one counter-family refutes it. That is the honest
outcome, and a better finding than the flat claim would have been: **the PKI-layer cost profile of PQC
is family-dependent — ML-DSA is size-bound, SLH-DSA is size- and compute-bound.** SLH-DSA's reputation
for slow *signing* is well known; that its *verification*, and therefore path validation, is also
non-trivial at high security levels is the part that a handshake-focused study would miss.

(Note the classical baseline itself is not uniform: RSA-3072 validates ~6× faster than ECDSA P-256 in
this JDK+BC stack. The report gives both so no comparison rests on a single anomalous baseline.)

## 3. Where the bytes go: ML-DSA is balanced, SLH-DSA is all signature (RQ3)

Decomposing a single leaf certificate into public key / signature / fixed overhead:

| | public key | signature | signature share |
|---|---|---|---|
| ML-DSA-65 | 1,974 B | 3,309 B | 61% |
| SLH-DSA-128f | 50 B | 17,088 B | **99%** |
| SLH-DSA-256f | 82 B | 49,856 B | **99%** |

ML-DSA spends its bytes on a large public key *and* a large signature — both travel in the certificate.
SLH-DSA has a ~50-byte public key and puts essentially everything into the signature. This matters for
deployment: an SLH-DSA public key is cheap to cache, pin, or embed, and the cost is entirely in the
per-certificate signature; an ML-DSA key is itself kilobytes. The fixed X.509 overhead is a near-constant
~172 B across every algorithm, confirming the single-profile design isolates the cryptographic cost.

## 4. Composite costs ML-DSA plus a small classical increment (RQ4, H3 — supported)

A composite certificate carries a full ML-DSA signature and a full classical signature, so a verifier
that trusts either is protected. The overhead over pure ML-DSA is modest:

| | chain size | vs pure ML-DSA | validation |
|---|---|---|---|
| ML-DSA-65 | 10,905 B | — | 158 µs |
| MLDSA65-ECDSA-P384 | 11,299 B | 1.04× | 466 µs |
| MLDSA65-RSA3072-PSS | 12,463 B | 1.14× | 265 µs |

Size grows by only 4–14% — the classical signature and key are small next to ML-DSA's. Validation adds
the classical verification on top of the ML-DSA one (and inherits ECDSA's slowness where it uses P-384).
Hybrid protection at the PKI layer is, in size terms, nearly free relative to going PQC at all.

## 5. Everything scales linearly with tier depth (RQ5, H4 — supported)

Each added tier contributes one more transmitted certificate of essentially constant size, so both chain
size and validation time are linear in depth. ML-DSA-65 transmitted bytes at 2/3/4 tiers are
5,446 / 10,905 / 16,364 — a clean 1 : 2 : 3. This means the FPKI concern is straightforward to
extrapolate: a deep government hierarchy pays the per-certificate cost once per tier, with no
super-linear surprise.

## Threshold crossings

At 3 tiers, the SLH-DSA `f` variants (128f, 192f, 256f) each produce a **single certificate larger than
one TLS record** (16,384 B), and their chains exceed the **JDK default maximum handshake message size**
(32,768 B) — meaning such a chain is rejected by an out-of-the-box JDK TLS peer unless
`jdk.tls.maxHandshakeMessageSize` is raised. SLH-DSA-128s and all ML-DSA parameter sets stay under the
per-certificate record limit; the larger ML-DSA and composite chains still cross the 32 KB handshake
limit at depth. The parameter set, not just the family, decides whether a certificate fits.
