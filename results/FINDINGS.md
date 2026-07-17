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

---

# Part II — Breakage and path discovery

Part I compared measured sizes to documented limits and validated chains handed over in order. Part II
replaces the arithmetic with real handshakes, and measures path *discovery* over the cross-certified
hierarchies Federal PKI actually uses. Full output in [`TLS-READINESS.md`](TLS-READINESS.md) and
[`PATH-BUILDING.md`](PATH-BUILDING.md).

## 6. Java cannot authenticate with PQC certificates yet — the first wall is auth, not size (RQ6)

Driving real TLS 1.3 handshakes on the loopback interface, **every** ML-DSA, SLH-DSA and composite leaf
fails on **both** JSSE providers; the classical controls all pass.

| | SunJSSE | BCJSSE |
|---|---|---|
| ECDSA P-256, RSA-3072 | authenticates | authenticates |
| all ML-DSA / SLH-DSA / composite | `handshake_failure` | `handshake_failure` |

The cause is authentication negotiation, not size. A `-Djavax.net.debug` trace shows the JSSE
`ClientHello` advertising only classical `signature_algorithms` — `ecdsa_*`, `ed25519/448`, `rsa_pss_*`,
`rsa_pkcs1_*` — with no ML-DSA or SLH-DSA codepoint at all. A server holding a post-quantum leaf has no
scheme to negotiate, so it aborts. The TLS 1.3 signature-scheme codepoints for these algorithms are still
IETF drafts (`draft-ietf-tls-mldsa`, `draft-tls-reddy-slhdsa`) and are unimplemented in JDK 21 and in
BouncyCastle's JSSE provider 1.85. **PQC certificate authentication in standard Java is not slow or large
— it does not complete at all.**

## 7. The size wall is exactly where Part I predicted (RQ7)

Holding the algorithm classical (so authentication succeeds) and growing the chain to each real
post-quantum chain's measured size isolates size as the only variable:

| Chain sized like | ~Transmitted bytes | Handshake |
|---|---|---|
| ML-DSA-44/65/87 | 7.8–14.8 KB | completes |
| SLH-DSA-128s | 16.1 KB | completes |
| all composites | 8–15 KB | completes |
| **SLH-DSA-128f** | **34.6 KB** | **fails — size limit** |
| **SLH-DSA-192f** | **71.8 KB** | **fails — size limit** |
| **SLH-DSA-256f** | **100.2 KB** | **fails — size limit** |

The failure is precise: `SSLProtocolException: The size of the handshake message (34588) exceeds the
maximum allowed size (32768)`, the default `jdk.tls.maxHandshakeMessageSize`. This confirms Part I's
threshold analysis empirically: the SLH-DSA `f` variants are exactly the chains that cross the 32 KB
default, and everything through ML-DSA-87 and SLH-DSA-128s fits. Raising the property admits them, so it
is a configuration ceiling — but it is the out-of-the-box default, and it is the *second* wall, met the
moment PQC authentication (the first wall) is fixed.

## 8. Path building is robust to cross-cert branching — even with multi-hop decoys (RQ8, negative result)

The plausible worry was that cross-certification — where one CA name carries many issuer certificates —
would make `CertPathBuilder` explore combinatorially and re-verify candidates, with the post-quantum
signature cost amplifying every wasted step. **It does not.** The test is deliberately hard: each of the
*k* candidate branches is **three intermediates deep** before dead-ending at an untrusted root, so a
decoy cannot be dismissed in one hop. Sweeping *k* from 1 to 32 (median build µs):

| Algorithm | k=1 | k=32 | growth | verify speed |
|---|---|---|---|---|
| ECDSA P-256 | 1,561 | 1,475 | 0.9× | fast |
| RSA-3072 | 245 | 552 | 2.3× | fast |
| ML-DSA-65 | 436 | 662 | 1.5× | fast |
| SLH-DSA-128f | 7,695 | 8,646 | 1.1× | slow |
| SLH-DSA-256f | 11,776 | 15,679 | 1.3× | slow |

The decisive observation is the *ordering*: the **slowest verifiers (SLH-DSA) are the least amplified**,
while the cheap-to-verify RSA/ML-DSA grow more in relative terms. If branching forced the builder to
verify dead-end candidates, the slow verifier would be hit hardest — the exact opposite of what we see.
So the modest growth is store-search overhead (more certificates to index and name-match), not signature
checks: the JDK builder finds the reaching branch without walking, or verifying, the multi-hop decoys.
This is reassuring for cross-certified FPKI — the Federal Bridge model creates no path-discovery blow-up
in the JDK, classical or post-quantum.

## 9. The cost is in path depth, and there the PQC verify price is paid in full (RQ9)

Holding branching fixed and lengthening the discovered path from 4 to 7 certificates, build time rises
~1.8× **across every algorithm** — uniform in ratio because each added certificate is one more signature
to verify, so cost tracks path length times the per-verify price. That price is where the algorithms
diverge. On the realistic depth-five Federal-Bridge path (Common Policy Root → Federal Bridge → agency CA
→ sub-CA → leaf, with decoy partner cross-certificates):

| Algorithm | build (median) |
|---|---|
| RSA-3072 | 185 µs |
| ML-DSA-65 | 411 µs |
| ML-DSA-87 | 624 µs |
| SLH-DSA-128f | 6.2 ms |
| SLH-DSA-256f | 9.6 ms |

So the "bytes *and* CPU" character of SLH-DSA (finding 2) reappears at the path-discovery layer: a deep
government hierarchy authenticated with SLH-DSA costs milliseconds to discover a path for, ~50× a
classical one, entirely from verification along the depth-five path. ML-DSA stays sub-millisecond, in
keeping with its size-bound (not CPU-bound) profile.

## 10. A third JDK ceiling: the default maximum path length (RQ8/RQ9, incidental)

The depth experiment surfaced a limit worth naming alongside the TLS ones. `PKIXBuilderParameters`
defaults `maxPathLength` to **5** non-self-issued intermediate certificates; a cross-certified path five
intermediates deep is rejected before any signature is checked unless the caller raises it (the harness
sets it unlimited so it can measure past the default). Deep FPKI hierarchies — a Common Policy Root, a
bridge, an agency principal CA, a sub-CA, plus cross-cert hops — reach this depth, so the default is a
third out-of-the-box ceiling a government-scale post-quantum deployment can meet, after PQC
authentication support (§6) and the TLS handshake-message size (§7).

## 11. JDK 27 and JEP 527: the KEM half arrives, the signature half does not (RQ6 revisited)

The obvious objection to §6 is that it measures a moving target: perhaps the newest JDK fixes it. It does
not — and the way it does not is itself the finding. **JDK 27** ships JEP 527, "Post-Quantum Hybrid Key
Exchange for TLS 1.3", so it is the first JDK to add post-quantum cryptography to the TLS stack. Running
the identical readiness harness on JDK 27 EA (build 31), **every post-quantum certificate still fails to
authenticate**, exactly as on JDK 21 ([`TLS-READINESS-jdk27.md`](TLS-READINESS-jdk27.md)).

Reading the supported `SSLParameters` off each JDK's default provider shows precisely why:

| Capability | JDK 21 | JDK 27 (EA+31) |
|---|---|---|
| ML-KEM hybrid key exchange (`X25519MLKEM768`) | absent | **present** (JEP 527) |
| PQC signature scheme (ML-DSA / SLH-DSA) | absent | **absent** |
| Advertised signature schemes | classical only¹ | classical only (21 schemes, all classical) |
| PQC certificate authentication | fails | **fails** |

¹ JDK 21 does not report signature schemes through `SSLParameters`; its ClientHello advertises only
`ecdsa_*`, `ed25519/448`, `rsa_pss_*`, `rsa_pkcs1_*`, observed by handshake trace.

The transition has two halves, and JDK 27 has shipped exactly one. **Key exchange** is done: ML-KEM is a
first-class named group, so the confidentiality side of post-quantum TLS works out of the box.
**Authentication** is untouched: there is no ML-DSA or SLH-DSA signature scheme, so the certificate/PKI
layer — the entire subject of this study, and where the size and validation costs measured in Parts I–II
live — remains classical-only even in the release that introduced post-quantum TLS. The signature-scheme
codepoints are still IETF drafts (`draft-ietf-tls-mldsa`, `draft-tls-reddy-slhdsa`), and until they land
in JSSE, the sizes this project measures cannot yet be paid on the wire — the certificates that would
carry them cannot complete a handshake on any shipping JDK.
