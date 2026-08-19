"""Agent-orchestration record/replay -- the genuinely-new core (no vendor ships it).
An agent is any function of a Session exposing .llm() and .tool(). Record mode runs
under production batch load and commits (tokens + logit-hashes) and tool I/O to the
event log. Replay mode re-drives the SAME agent alone: LLM calls are recomputed
deterministically, tool calls are re-injected from the log. If inference is
batch-invariant, the replay event log is byte-identical -> the record-time certificate
verifies against it. If not, the logit-hashes diverge and the certificate fails.
"""
from __future__ import annotations
from .events import EventLog, Kind, h as hash_text
from .capability import Broker, recorded_tool_results
from .certificate import issue_certificate

class Session:
    def __init__(self, lm, caps, tools, invariant, recorded: EventLog | None = None, prod_load=0):
        self.lm = lm
        self.invariant = invariant
        self.recorded = recorded
        self.prod_load = prod_load
        self.log = EventLog()
        rr = recorded_tool_results(recorded) if recorded is not None else None
        self.broker = Broker(caps, tools, self.log, replay=rr)

    def llm(self, prompt: str, n_new=8):
        load = 0 if self.recorded is not None else self.prod_load   # replay runs alone
        toks, hashes = self.lm.generate(prompt, n_new=n_new, batch_load=load, invariant=self.invariant)
        text = self.lm.tok.decode(toks, skip_special_tokens=True)
        self.log.append(Kind.LLM_CALL, {"prompt_hash": hash_text(prompt), "tokens": toks,
                                        "logit_hashes": hashes, "text": text})
        return text

    def tool(self, name: str, *args):
        return self.broker.call(name, *args)

def record_run(agent_fn, lm, caps, tools, key, prog_hash, prod_load=8, invariant=True, priv=None):
    s = Session(lm, caps, tools, invariant, recorded=None, prod_load=prod_load)
    agent_fn(s)
    cert, _ = issue_certificate(prog_hash, caps, s.log, priv=priv, key=(None if priv else key))
    return s.log, cert

def replay_run(agent_fn, lm, caps, tools, recorded: EventLog, invariant=True):
    s = Session(lm, caps, tools, invariant, recorded=recorded, prod_load=0)
    agent_fn(s)
    return s.log
