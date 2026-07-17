# Experimental Design — The Cost of Post-Quantum Cryptography at the X.509 PKI Layer in Java

**Working title:** *Certificates, Not Handshakes: Measuring the PKI-Layer Cost of Post-Quantum
Signatures in Java*

**Author:** Arpan Sharma
**Status:** Design draft v0.1 — pre-registration of research questions, hypotheses, and method. The
toolchain has been de-risked (see §11); no measurement data collected yet.
**Repository:** `pqc-pki-certpath` (standalone).

---

## 1. Motivation and gap

Most measurement of the post-quantum transition studies the **TLS handshake**: the cost of ML-KEM in key
exchange, handshake latency, round-trip behaviour. The **PKI layer** underneath it — the X.509
certificates and the path validation that authenticates a peer — is far less studied, yet it is where
the large post-quantum *signatures* multiply. Every certificate in a chain carries a signature, and a
realistic chain has several: a leaf signed by an intermediate, signed by a root. A classical ECDSA chain
is a few hundred bytes; the same chain with SLH-DSA signatures is tens of kilobytes.

This matters for three reasons:

- **It is the least-studied layer of the migration.** Handshake-level PQC benchmarks are common; a
  systematic Java measurement of certificate chain sizes and `CertPath` validation cost is not.
- **It is on the federal roadmap.** CNSA 2.0 puts Federal PKI (FPKI) migration explicitly in scope, and
  FPKI is a deep, multi-tier hierarchy — exactly the structure whose per-tier signature cost this study
  quantifies.
- **Java runs enterprise and government PKI.** The JDK's `java.security.cert` stack (`CertPathValidator`,
  `CertPathBuilder`, `PKIXParameters`) is the validation engine behind a large fraction of that
  infrastructure, and its behaviour with PQC certificates has not been measured.

The question this project answers is not "is PQC expensive" in the abstract, but *where* the expense
falls at the PKI layer — and, as the pre-registered hypotheses make explicit, we expect the answer to be
**bytes, not validation CPU**.

## 2. What is measured, and against what

Three multi-tier X.509 hierarchies are generated per algorithm — `root → leaf` (2-tier),
`root → intermediate → leaf` (3-tier, the primary case), and `root → intermediate → intermediate → leaf`
(4-tier) — and for each we measure:

| Quantity | How | Nature |
|---|---|---|
| Per-certificate size, decomposed into TBSCertificate / public key (SPKI) / signature value | ASN.1 structure of each cert | deterministic (per parameter set) |
| Total transmitted chain size (leaf + intermediates; the root is a trust anchor, not sent) | sum of encoded certs | deterministic |
| Path validation time | `CertPathValidator.getInstance("PKIX").validate(...)`, warmed up and repeated | host-specific |
| Threshold crossings | measured chain size vs the limits in §6 | deterministic |

**Baselines and comparators (one held-fixed certificate profile for all):**

- **Classical:** ECDSA P-256, RSA-3072 — the incumbents PQC replaces.
- **ML-DSA (lattice, FIPS 204):** ML-DSA-44, ML-DSA-65, ML-DSA-87.
- **SLH-DSA (hash-based, FIPS 205):** SHA2-128f, SHA2-128s, SHA2-192f, SHA2-256f — spanning the `f`
  (fast/large) vs `s` (small/slow) trade-off, whose *size* axis is what matters here.
- **Composite (IETF LAMPS draft, hybrid):** MLDSA44-ECDSA-P256, MLDSA65-ECDSA-P384, MLDSA65-RSA3072-PSS,
  MLDSA87-ECDSA-P521 — a PQC and a classical signature carried together, so a verifier trusting either
  is protected.

The certificate profile (validity, DN structure, extensions: BasicConstraints + KeyUsage) is identical
across every algorithm, so all size and time differences are attributable to the cryptography, not to
certificate content.

## 3. Research questions

- **RQ1 (chain size).** How large do X.509 chains become with PQC signatures, by parameter set and tier
  depth? Where do they cross the size thresholds real systems assume (§6)?
- **RQ2 (validation cost).** What does PKIX path validation cost per algorithm, relative to classical
  ECDSA/RSA — and is validation CPU, or size, the dominant PKI-layer cost of PQC?
- **RQ3 (size decomposition).** Within a certificate, how is the cost split between the public key and
  the signature? This separates ML-DSA (large key *and* signature) from SLH-DSA (tiny key, dominant
  signature), which have very different implications for caching and reuse.
- **RQ4 (hybrid/composite).** What is the size and validation overhead of composite (PQC + classical)
  certificates over pure PQC, and over classical?
- **RQ5 (scaling in depth).** How do chain size and validation time scale as tier depth grows from 2 to
  4 — linearly, as the per-certificate model predicts, or otherwise?

## 4. Hypotheses (pre-registered)

- **H1 (size is orders of magnitude).** PQC chains are at least one order of magnitude larger than a
  classical (ECDSA P-256) chain of the same depth. Concretely, and precisely because the pilot sizing
  in §11 shows the SLH-DSA parameter sets differ sharply: every SLH-DSA **`f` (fast)** certificate
  individually exceeds one TLS record (16,384 bytes), and a 3-tier chain of any SLH-DSA `f` variant
  exceeds the JDK's default maximum handshake message size (32,768 bytes). The smaller `s` variants are
  predicted *not* to cross the single-record limit per certificate — the parameter set, not just the
  family, decides whether a certificate fits.
- **H2 (the cost is bytes, not CPU).** ML-DSA path validation is competitive with classical RSA-3072 —
  within a small constant factor — and even SLH-DSA *verification* (as opposed to signing) stays cheap.
  The dominant PKI-layer cost of PQC is therefore the transmitted size, not validation time. This is the
  central, non-obvious claim: SLH-DSA is notorious for slow *signing*, but path validation only
  *verifies*, and hash-based verification is fast.
- **H3 (composite ≈ ML-DSA + a classical increment).** A composite certificate costs, in both size and
  validation time, its ML-DSA component plus a modest classical increment — much closer to pure ML-DSA
  than to double it.
- **H4 (linear in depth).** Both total chain size and total validation time scale linearly with tier
  depth, since each added tier contributes one more certificate and one more signature verification.

A confirmed H2 reframes the usual narrative: for path validation specifically, the PQC migration is a
*bandwidth and storage* problem, not a *compute* one. That framing, quantified in Java, is the
contribution.

## 5. Methodology

1. **Hierarchy generation.** For each algorithm and tier depth, generate a hierarchy with BouncyCastle
   (`X509v3CertificateBuilder` + `JcaContentSignerBuilder`), keys drawn from a seeded deterministic RNG
   so the whole experiment is reproducible. CA certificates carry BasicConstraints(cA=true) and
   KeyUsage(keyCertSign); the leaf carries KeyUsage(digitalSignature).
2. **Size measurement.** Encode each certificate (DER) and record its total length; parse its ASN.1
   `Certificate` structure to record the TBSCertificate, SubjectPublicKeyInfo, and signatureValue
   lengths separately (RQ3). Sizes are deterministic per parameter set; for algorithms whose signature
   encoding has variable length (ECDSA and composites embedding it), report across several generated
   keys.
3. **Validation benchmark.** Build a `CertPath` of (leaf, intermediates…) and validate it against the
   root trust anchor using the JDK's `PKIX` `CertPathValidator`, with revocation disabled (no OCSP/CRL:
   we isolate cryptographic path validation, not network lookups). Warm up, then take many timed repeats;
   report median and inter-quartile range, not the mean, because JIT and GC make the distribution
   skewed. The JDK validator delegates signature verification to the registered BouncyCastle provider —
   verified during de-risking (§11).
4. **Threshold evaluation.** Compare each measured chain size against the §6 thresholds and report every
   crossing.

The JDK's own `PKIX` validator is the primary engine, deliberately: it is what a standard Java
application uses, so its behaviour is the representative one. BouncyCastle's `PKIX` validator may be
added as a secondary comparison.

## 6. Size thresholds (the "breaks assumptions" reference points)

| Threshold | Value | Source / meaning |
|---|---|---|
| TLS record plaintext | 16,384 bytes (2¹⁴) | RFC 8446 §5.1. A larger handshake message is fragmented across records — not fatal, but buffers and middleboxes sometimes assume a message fits one record. |
| JDK max handshake message | 32,768 bytes (default) | `jdk.tls.maxHandshakeMessageSize`. A `Certificate` message larger than this is rejected by the JDK TLS stack unless the property is raised. |
| JDK max certificate chain length | 10 certificates (default) | `jdk.tls.maxCertificateChainLength`. A depth limit, not a size limit; relevant to deep FPKI hierarchies. |

These are cited as fixed reference points. This study measures the PKI primitives (`CertPath`), it does
not drive a live TLS handshake; the crossings are computed from measured certificate sizes against these
documented limits.

## 7. Metrics and reporting

Per (algorithm, tier depth): per-certificate sizes with the TBS/SPKI/signature split, total chain size,
validation time (median + IQR over the repeats), and a table of threshold crossings. A Markdown summary
and a machine-readable CSV are written under `results/`. The classical baselines anchor every comparison
as a multiple ("ML-DSA-65 chains are N× an ECDSA P-256 chain").

## 8. Threats to validity

- **Timing is host- and JIT-specific.** Validation time depends on the machine, the JDK, and warmup.
  Mitigated with warmup, many repeats, and robust statistics (median/IQR); the host and JDK are recorded
  with every result. Reported as host-specific, not absolute.
- **Sizes are the robust results.** Certificate encoded sizes are deterministic functions of the
  parameter set and the (fixed) certificate profile, so the size findings are host-independent and
  exact.
- **Provider-specific.** Results are tied to BouncyCastle (pinned) and the JDK `PKIX` validator (pinned);
  the validator delegates signature verification to BouncyCastle. A different provider could differ,
  which is recorded as a scope limit.
- **Not a live TLS measurement.** We measure certificate sizes and `CertPath` validation, and compare
  sizes to documented TLS/JDK limits; we do not run a TLS handshake. Handshake-level effects (record
  fragmentation cost, congestion-window interaction) are explicitly out of scope — they belong to the
  handshake layer this study is deliberately *not* about.
- **Certificate profile choice.** Absolute sizes shift a little with DN length and extension set; these
  are held identical across algorithms so every comparison is fair, and the profile is recorded.
- **ECDSA/composite size variance.** ECDSA signature values are DER-encoded integers of variable length,
  so certs embedding them vary by a few bytes between keys. Reported across multiple keys rather than as
  a single figure.

## 9. Reproducibility and disclosure

Pinned JDK 21, BouncyCastle 1.85, deterministic key-generation seeds, and a fixed certificate profile
make every size exact and every timing reproducible in distribution. This is a measurement study, not a
vulnerability study; there is nothing to disclose. The harness and the generated hierarchies are
committed so any figure can be regenerated.

## 10. Deliverables and target venues

- **Artifact:** an open-source Java harness that generates multi-tier PQC, classical, and composite X.509
  hierarchies and benchmarks their chain sizes and `CertPath` validation cost — reusable for any
  parameter set BouncyCastle exposes.
- **Paper:** the first Java PKI-layer measurement of the PQC transition, with the size/CPU decomposition
  and the threshold-crossing analysis.
  - Venues: ACM SAC, IEEE CNS, ARES.

## 11. De-risking (completed before this design was finalised)

The critical unknown — whether the JDK's `PKIX` `CertPathValidator` can validate PQC certificate chains
at all — was resolved before committing to the design. A probe confirmed, on BouncyCastle 1.85 + JDK 21:

- The JDK's own `PKIX` validator (`CertPathValidator.getInstance("PKIX")`, provider `SUN`) successfully
  validates 3-tier ML-DSA-65, SLH-DSA-SHA2-128F, and composite MLDSA65-ECDSA-P384 chains, delegating
  signature verification to the registered BouncyCastle provider. No custom validator is required.
- Certificate sizes decompose cleanly into TBS / SPKI / signature via the ASN.1 structure, confirming
  RQ3 is measurable. Early figures: ML-DSA-65 cert ≈ 5,411 bytes (1,974 key + 3,309 signature);
  SLH-DSA-SHA2-128s cert ≈ 8,033 bytes (50 key + 7,856 signature) — already illustrating the RQ3
  contrast.
- A single SLH-DSA-SHA2-128F certificate (≈ 17,304 bytes) already exceeds one TLS record, previewing H1.

These probe figures are illustrative; the committed harness regenerates all reported numbers.

## 12. Non-goals (Part I)

- Not a TLS handshake *performance* benchmark (handshake latency/throughput is the handshake layer,
  studied elsewhere). Part II does drive real handshakes, but to observe *breakage*, not to time them.
- Not a revocation study (OCSP/CRL network cost is disabled to isolate cryptographic validation).
- Not a security/robustness study of the parsers (that is the sibling `pqc-decode-fuzzing` project).
- Not constant-time or side-channel analysis (sibling `pqc-jvm-sidechannel`).

---

# Part II — Extended study: breakage and path discovery

The Part I measurements confirmed the size and validation costs but, by construction, only *compared
measured sizes to documented limits* and only *validated chains already in hand*. Part II closes those
two gaps with experiments added after Part I, motivated directly by the weakest points of the first
study: it replaces threshold arithmetic with demonstrated breakage, and it measures path *discovery*
over the cross-certified hierarchies that Federal PKI actually uses. These experiments were designed and
run after Part I; their questions are stated here and their findings reported honestly, including a
negative result.

## 13. TLS handshake readiness and breakage (RQ6, RQ7)

- **RQ6 (authentication readiness).** Can a standard Java TLS 1.3 stack — the JDK's `SunJSSE` and
  BouncyCastle's `BCJSSE` — actually complete a handshake authenticated by an ML-DSA or SLH-DSA
  certificate today?
- **RQ7 (size breakage).** At what chain size does a TLS handshake fail on message size alone, and which
  of the measured post-quantum chains cross it?

**Method.** Drive real loopback TLS 1.3 handshakes. For RQ6, a leaf signed by each algorithm, against
each provider, with classical algorithms as the control; classify each outcome as success, an
authentication failure, or a size failure. For RQ7, hold the algorithm classical (so authentication
succeeds) and grow the certificate chain — via a padding extension — to the measured size of each real
post-quantum chain, isolating size as the only variable. The two axes are orthogonal by design: RQ6
fails independent of size, RQ7 fails independent of algorithm.

**Found.** RQ6: *no* post-quantum handshake completes on either provider — all fail with
`handshake_failure`, because JSSE advertises only classical `signature_algorithms` (the PQC TLS 1.3
signature-scheme codepoints are still IETF drafts, unimplemented). RQ7: chains up to ~16 KB complete;
the SLH-DSA `f` variants (≥ ~34 KB) fail with `SSLProtocolException: ... exceeds the maximum allowed
size (32768)`, the JDK default `jdk.tls.maxHandshakeMessageSize`. So a Java PQC deployment meets an
authentication wall first, and a size wall the moment that is removed.

## 14. Path building over cross-certified hierarchies (RQ8, RQ9)

- **RQ8 (branching cost).** When a bridged CA name carries many issuer certificates — the Federal Bridge
  situation — does `CertPathBuilder` path discovery blow up with the branching factor, and does the
  post-quantum signature cost amplify it?
- **RQ9 (realistic FPKI cost).** What does discovery cost on a realistic depth-five Federal-Bridge-shaped
  path, per algorithm?

**Method.** Build cross-certified stores where one CA name is issued a certificate by *k* different roots
(only one anchored), and sweep *k*; and a Federal-Bridge-shaped hierarchy (Common Policy Root → Federal
Bridge → agency CA → sub-CA → leaf) with decoy partner cross-certificates. Benchmark
`CertPathBuilder.build` discovery time with warmup and repeats.

**Found.** RQ8 (a **negative result**, and a reassuring one): discovery is essentially flat in *k* — from
1 to 32 candidate issuers, build time moves < 1.1× even for SLH-DSA. The JDK builder prunes candidates by
name and trust-anchor priority before verifying signatures, so cross-certificate branching does *not*
create a post-quantum-amplified blow-up. RQ9: discovery cost is dominated by the per-signature
verification along the discovered path and scales with path depth — the depth-five SLH-DSA-256F path
costs ~9 ms to discover versus ~0.2 ms for RSA-3072, reinforcing that SLH-DSA is expensive on CPU as well
as size, now at the discovery layer too.

## 15. Positioning against related work

The closest related work (an experimental study of ML-DSA/SLH-DSA *signature placement* in TLS 1.3
certificate hierarchies) is in C, over OpenSSL/liboqs, measures handshake *performance*, and explicitly
does not address CertPath validation, path building, cross-certification/bridge CAs, or failure. Federal
PKI runs a real post-quantum cross-certification testbed (an ML-DSA-87 root and Bridge CA for path
discovery). This project is complementary and distinct: it is the **Java/JDK** measurement, it covers
**path building** and **cross-certified/FPKI** topologies, and it reports **demonstrated breakage** — the
axes that body of work leaves open.

---

*Pre-registration: the Part I research questions, hypotheses, algorithm set, certificate profile, and
size thresholds were fixed before data collection so the results carry the weight of a prediction. Part
II was added afterwards and is reported as such — including its negative result (RQ8) stated plainly
rather than reframed.*
