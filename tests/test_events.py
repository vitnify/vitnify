"""Event log: canonical form, hash-chaining, Merkle event_root/head, and the
tamper-evidence property (change any event -> the root changes)."""
from __future__ import annotations

import pytest

from vitnium.events import EventLog, Kind, canon, h
from vitnium._vendor.pck.cas import MerkleCAS

from conftest import build_log, clone


def test_chain_links_each_event_to_its_predecessor(agent_log):
    events = agent_log.events
    assert events[0].prev == "genesis"
    for prev, cur in zip(events, events[1:]):
        assert cur.prev == prev.hash


def test_indices_are_sequential(agent_log):
    assert [e.i for e in agent_log.events] == list(range(len(agent_log)))


def test_head_is_last_event_hash(agent_log):
    assert agent_log.head() == agent_log.events[-1].hash


def test_empty_log_head_is_genesis():
    assert EventLog().head() == "genesis"


def test_canonical_form_is_sorted_compact_json(agent_log):
    e = agent_log.events[0]
    assert e.canonical() == canon(
        {"i": e.i, "kind": e.kind, "payload": e.payload, "prev": e.prev})
    assert e.hash == h(e.canonical())


def test_log_construction_is_deterministic():
    a = build_log([])
    b = build_log([])
    assert a.chunks() == b.chunks()
    assert a.head() == b.head()
    assert MerkleCAS(a.chunks()).root == MerkleCAS(b.chunks()).root


def test_model_digests_extracted_from_llm_calls():
    log = EventLog()
    log.append_llm_call("ph0", [1, 2], seed=0, model_digest="d0")
    log.append(Kind.TOOL_CALL, {"tool": "t", "decision": "allow", "result": "r"})
    log.append_llm_call("ph1", [3, 4], seed=0, model_digest="d1")
    assert log.model_digests() == ["d0", "d1"]


def test_event_root_and_head_are_stable_across_rebuild(agent_log):
    root1 = MerkleCAS(agent_log.chunks()).root
    root2 = MerkleCAS(clone(agent_log).chunks()).root
    assert root1 == root2


# Every event position + field, mutated one at a time -> the Merkle root must move.
_MUTATIONS = {
    "edit_prompt_hash":  lambda log: log.events[0].payload.__setitem__("prompt_hash", "deadbeef"),
    "edit_tokens":       lambda log: log.events[0].payload.__setitem__("tokens", [9, 9, 9]),
    "edit_logit_hashes": lambda log: log.events[0].payload.__setitem__("logit_hashes", ["x", "y", "z"]),
    "flip_tool_decision": lambda log: log.events[2].payload.__setitem__("decision", "ALLOW"),
    "edit_tool_args":    lambda log: log.events[1].payload.__setitem__("args", ["forged"]),
    "edit_entropy":      lambda log: log.events[-1].payload.__setitem__("value", "0x9999"),
    "reorder_events":    lambda log: log.events.__setitem__(slice(1, 3), log.events[1:3][::-1]),
    "truncate_last":     lambda log: log.events.pop(),
    "delete_middle":     lambda log: log.events.pop(1),
}


@pytest.mark.parametrize("mutate", list(_MUTATIONS.values()), ids=list(_MUTATIONS))
def test_any_event_mutation_changes_the_merkle_root(agent_log, mutate):
    original_root = MerkleCAS(agent_log.chunks()).root
    tampered = clone(agent_log)
    mutate(tampered)
    assert MerkleCAS(tampered.chunks()).root != original_root
