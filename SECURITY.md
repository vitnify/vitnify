# Security Policy

vitnify produces execution receipts that other parties rely on to prove what an agent
did. A vulnerability here can let a run be forged, a tampered transcript pass
verification, or a contained agent reach a capability it was never granted. Those are
exactly the outcomes this project exists to prevent, so we want your reports.

## Reporting a vulnerability

**Email [security@vitnify.com](mailto:security@vitnify.com).** Please do **not** open a
public GitHub issue, pull request, or discussion for a suspected vulnerability — that
discloses it before there is a fix.

A private GitHub Security Advisory (Security ▸ *Report a vulnerability*) is also fine.

A useful report includes:

- the affected area (verification, certificate issuance/signing, the capability Broker,
  the event log / canonical JSON, an adapter, the L2 recompute path);
- a minimal proof of concept — the attack-matrix tests in
  `tests/test_attack_matrix.py` are a good model for how to express one;
- what you observed vs. what should have happened (e.g. "a receipt with a reordered
  event log still verified at level 1");
- the version/commit, Python version, and any optional extras installed
  (`[langgraph]`, `[mcp]`).

## What's in scope

The properties a receipt is supposed to guarantee — break any of these and we want to
know:

- **Verification soundness.** Any tampered, reordered, truncated, or forged transcript
  that passes level-1 verification; any signature-verification bypass; any receipt that
  verifies against a public key that did not sign it.
- **Capability containment escape.** Any way for an *ungranted* tool to be invoked, or
  for a side effect to occur, without going through the Broker and being recorded as an
  allow/deny in the log.
- **Canonicalization / hashing flaws.** Two different logs that produce the same
  `event_root`, `head_hash`, or receipt digest; canonical-JSON ambiguities that let a
  payload be mutated without changing the hash.
- **Determinism / L2 soundness.** Any way an `llm_call` `model_digest` verifies at
  level 2 for a computation that was not actually performed.
- **Cryptographic misuse** — weak or predictable key generation, nonce/seed handling,
  timing side channels in verification.

## Not in scope

- The stated trust-boundary limit: an embedded ed25519 key proves signer continuity,
  not that the signer was an authorized runtime. A receipt re-signed by a different key
  self-verifies by design; provenance requires a pinned trust anchor. This is documented,
  not a bug.
- Vulnerabilities in third-party optional dependencies (`langgraph`, `mcp`,
  `cryptography`, `blake3`) themselves — report those upstream — unless our usage is what
  makes them exploitable.
- Denial of service from feeding an intentionally enormous log or model.

## Response expectations

- We will **acknowledge your report within 3 business days**.
- We will confirm the issue and share an assessment, typically within 10 business days.
- We will keep you posted through the fix and coordinate a disclosure timeline with you.
  We are happy to credit you unless you prefer to stay anonymous.

## Safe harbor

We will not pursue or support legal action against anyone who, in good faith, follows
this policy while investigating or reporting a security issue — accessing only what is
necessary to demonstrate the problem, avoiding privacy violations and service
disruption, and giving us reasonable time to respond before public disclosure. We
consider good-faith security research to be authorized conduct and will work with you.
If in doubt, ask first at security@vitnify.com.
