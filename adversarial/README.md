# vitnify adversarial probes

`verify_certificate()` is the trust boundary of this project — if it says a receipt
is valid, you're meant to believe it. So don't take our word that it's sound: attack it.

[`probe_suite.py`](probe_suite.py) builds a forged or tampered receipt for every class
of attack we know and asserts the **shipped** verifier rejects each one. It imports
whatever `vitnify` is installed, so you can point it at any release:

```
pip install vitnify            # or ==0.1.0 to watch older ones fail
python adversarial/probe_suite.py
```

Exit code `0` means every attack was blocked and an honest receipt still verifies.

The suite covers unsigned and keyless-HMAC receipts, out-of-policy tool calls,
edited / deleted / reordered events, swapped model digests, rewritten chain pointers,
backdated timestamps, decision-string and event-kind relabelling, and a receipt
re-signed by an unauthorised key — the one documented trust-boundary limit, blocked
once you pin a trusted key.

Found one that gets through? That's the finding we care about most:
**security@vitnify.com**. This suite is meant to grow.
