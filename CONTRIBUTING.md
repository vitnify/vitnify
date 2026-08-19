# Contributing to vitnify

Thanks for helping build execution receipts for AI agents. The SDK contains,
deterministically reconstructs, and cryptographically certifies an agent run — so
correctness and reproducibility are the whole product, not a nice-to-have. Please read
the determinism rule below before you start.

## The one rule that is non-negotiable: determinism

> **A change must not alter the reference model-computation digest.**
>
> Reference (TinyLlama-1.1B-Chat, Q4_K_M GGUF, model_id `tinyllama-1.1b-chat-Q4_K_M`,
> prompt `[1, 9038, 2501, 263, 931, 29892]`, `n_new = 20`):
>
> ```
> 9c0754458633e863e0fb5bb2bd00df0d8b813934687b9a4097a1a9a4179f3b0f
> ```

This digest is a published conformance anchor (see the
[receipt spec](https://github.com/vitnify/vitnify-receipt-spec)); the engine emits it and
the SDK binds it into every receipt. **Any PR that changes it will be rejected** unless it
is an explicit, agreed-upon versioned migration — proposed in an issue first, with the
anchor updated in lockstep across the engine, SDK, and spec.

For the SDK specifically, this also means: **do not change how a receipt or event is
canonicalized or hashed** without a version bump. `event_root`, `head_hash`, and the
receipt digest are computed over canonical JSON (UTF-8, keys sorted, no whitespace); any
change to that byte layout breaks every existing receipt's verification. The
attack-matrix tests exist to catch exactly this.

## Build & test

Requires Python 3.10+ (CI runs 3.11). From the repo root:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m pytest
```

This runs the level-1 (offline integrity), unit, capability-containment, ed25519, and
attack-matrix suites — all with no model or network.

Two families of tests skip themselves unless their dependencies are present, and CI runs
green with them skipped:

- **Level-2 recomputation** (`tests/test_l2_recompute.py`, marked `l2`) re-runs each
  model step through the engine and needs both env vars set:

  ```bash
  VITNI_GGUF=tinyllama.gguf VITNI_RECEIPT_BIN=/path/to/vitni-receipt python -m pytest -m l2
  ```

  Run this locally whenever you touch anything on the model / digest path — it is how you
  confirm the reference digest above still reproduces.

- **Adapter integration** (`tests/test_adapters.py`, marked `adapter`) needs the optional
  extras: `pip install -e ".[dev,langgraph,mcp]"`.

Run a focused subset with, e.g., `python -m pytest tests/test_attack_matrix.py -q`.

## Pull requests

- Keep changes focused; explain *why*.
- Add or update tests. New verification/containment behavior belongs alongside the
  attack-matrix and capability suites so a regression can't silently pass.
- If your change is anywhere near the receipt/event/digest path, run the L2 suite locally
  and confirm the reference digest is unchanged.
- Keep public behavior backward-compatible with existing receipts unless you are doing a
  versioned format change.

## Sign your commits (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/). Sign off
every commit — it certifies you have the right to contribute the code:

```bash
git commit -s -m "your message"
```

This adds a `Signed-off-by: Your Name <you@example.com>` line. Commits without it will be
asked to amend.

## Reporting bugs vs. vulnerabilities

Ordinary bugs → open a GitHub issue. **Security issues** (a verification bypass, a
capability-containment escape, a canonicalization/collision flaw) → **do not** open a
public issue; email [security@vitnify.com](mailto:security@vitnify.com). See
[SECURITY.md](SECURITY.md).

By contributing you agree your contributions are licensed under Apache-2.0. Note that the
**vitnify** and **vitnify-verified** marks are trademarks — see [TRADEMARKS.md](TRADEMARKS.md).
