"""Certificate issuance + digest determinism.

The receipt digest is BLAKE3 over a canonical body. Same inputs -> same digest;
any change to a bound field -> a different digest. The wire format must not drift,
so these tests pin the body key set and the canonical-JSON encoding.
"""
from __future__ import annotations

import json

import pytest

from vitnify.certificate import (
    ExecutionCertificate, FORMAT, issue_certificate, _canon,
)

from conftest import CAPS, build_log


def _cert(**over):
    base = dict(program_hash="prog", capabilities=["read_public"],
                event_root="root0", n_events=3, head_hash="head0",
                model_digests=["d0"])
    base.update(over)
    return ExecutionCertificate(**base)


def test_body_has_exactly_the_bound_fields():
    assert set(_cert().body()) == {
        "v", "program_hash", "capabilities", "event_root",
        "n_events", "head_hash", "model_digests",
        "issued_at", "nonce", "run_id"}


def test_body_does_not_include_the_signature():
    # The signature signs the digest; it must not be part of the signed body.
    assert "sig" not in _cert().body()
    assert "pubkey" not in _cert().body()


def test_canon_is_sorted_and_compact():
    obj = {"b": 1, "a": [2, 3]}
    assert _canon(obj) == '{"a":[2,3],"b":1}'
    assert _canon(obj) == json.dumps(obj, sort_keys=True, separators=(",", ":"))


def test_digest_is_deterministic():
    assert _cert().digest() == _cert().digest()


def test_capabilities_are_order_independent_in_the_digest():
    a = _cert(capabilities=["read_public", "read_docs"])
    b = _cert(capabilities=["read_docs", "read_public"])
    assert a.digest() == b.digest()


@pytest.mark.parametrize("field,value", [
    ("program_hash", "other"),
    ("capabilities", ["read_public", "send_external"]),
    ("event_root", "root1"),
    ("n_events", 4),
    ("head_hash", "head1"),
    ("model_digests", ["d0", "d1"]),
    ("issued_at", "2020-01-01T00:00:00Z"),
    ("nonce", "ff" * 16),
    ("run_id", "run-x"),
    ("v", "vitnify-receipt v1"),
])
def test_changing_any_bound_field_changes_the_digest(field, value):
    assert _cert(**{field: value}).digest() != _cert().digest()


def test_issue_binds_root_head_count_and_model_digests(agent_log, ed_keys):
    priv, _ = ed_keys
    cert, cas = issue_certificate("prog", CAPS, agent_log, priv=priv)
    assert cert.v == FORMAT
    assert cert.event_root == cas.root
    assert cert.head_hash == agent_log.head()
    assert cert.n_events == len(agent_log)
    assert cert.model_digests == agent_log.model_digests()


def test_identical_runs_share_computation_but_get_unique_receipts(ed_keys):
    priv, _ = ed_keys
    log_a, log_b = build_log([]), build_log([])
    cert_a, _ = issue_certificate("prog", CAPS, log_a, priv=priv)
    cert_b, _ = issue_certificate("prog", CAPS, log_b, priv=priv)
    # The bound COMPUTATION is deterministic: identical runs commit to the same
    # event root and model digests.
    assert cert_a.event_root == cert_b.event_root
    assert cert_a.model_digests == cert_b.model_digests
    # ...but each receipt is UNIQUE -- nonce/run_id/issued_at differ -- so it can be
    # placed in time and one run's receipt can't be presented as another's.
    assert cert_a.nonce != cert_b.nonce
    assert cert_a.run_id != cert_b.run_id
    assert cert_a.digest() != cert_b.digest()
    assert cert_a.sig != cert_b.sig


def test_to_json_is_canonical_and_round_trips_fields(signed):
    cert = signed[0]
    payload = json.loads(cert.to_json())
    assert payload["v"] == FORMAT
    assert payload["sig_alg"] == "ed25519"
    assert payload["event_root"] == cert.event_root
