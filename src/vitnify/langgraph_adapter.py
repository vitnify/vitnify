"""LangGraph adapter — make a real LangGraph agent recordable, replayable, certifiable,
and contained, with no change to the agent's logic.

Two integration points:
  1. build_react_graph(session, ...) -> a compiled LangGraph StateGraph whose *agent*
     node calls session.llm() and whose *tool* node calls session.tool() (the capability
     wall). Because everything flows through the VitniReplay Session, the whole graph is
     recorded, deterministically replayable, and certified — for free.
  2. VitniReplayCallback(session) -> a LangChain BaseCallbackHandler that records LLM/tool
     events from ANY LangChain/LangGraph agent (observability + certificate). This path is
     record-only: callbacks observe but cannot re-inject, so it doesn't drive replay.
"""
from __future__ import annotations
from typing import TypedDict, Optional
from .react import parse_action, REACT_SYS
from .events import Kind

try:  # optional dependency: only needed to actually build/run the graph
    from langgraph.graph import StateGraph, START, END
    from langchain_core.callbacks import BaseCallbackHandler
    _IMPORT_ERROR: Exception | None = None
except ImportError as exc:  # keep the module importable without the extra installed
    StateGraph = START = END = None  # type: ignore[assignment]
    BaseCallbackHandler = object  # type: ignore[assignment,misc]
    _IMPORT_ERROR = exc


def _require_langgraph() -> None:
    """Raise a clear, actionable error if the LangGraph extra is not installed."""
    if _IMPORT_ERROR is not None:
        raise ImportError(
            "vitnify's LangGraph adapter requires 'langgraph' and 'langchain-core'. "
            'Install them with:  pip install "vitnify[langgraph]"'
        ) from _IMPORT_ERROR


class VRState(TypedDict, total=False):
    prompt: str
    steps: int
    last_text: str
    last_act: Optional[dict]


def initial_prompt(task: str, tools_desc: str) -> str:
    return (f"<|system|>\n{REACT_SYS.format(tools=tools_desc)}</s>\n"
            f"<|user|>\n{task}</s>\n<|assistant|>\n")


def build_react_graph(session, tools_desc: str, tool_names, max_steps: int = 3, n_new: int = 40):
    """Compile a LangGraph StateGraph wired to a VitniReplay Session."""
    _require_langgraph()

    def agent_node(state: VRState) -> VRState:
        text = session.llm(state["prompt"], n_new=n_new)          # recorded + recomputable
        act = parse_action(text, tool_names)
        return {"last_text": text, "last_act": act, "steps": state.get("steps", 0) + 1}

    def route(state: VRState) -> str:
        act = state.get("last_act")
        if act is None or "final" in act or state.get("steps", 0) >= max_steps:
            return "end"
        return "tools"

    def tool_node(state: VRState) -> VRState:
        act = state["last_act"]
        ok, obs = session.tool(act["tool"], *act["args"])          # capability wall
        observation = obs if ok else f"DENIED: agent has no capability '{act['tool']}'"
        return {"prompt": state["prompt"] + state["last_text"] + f"\nObservation: {observation}\n"}

    g = StateGraph(VRState)
    g.add_node("agent", agent_node)
    g.add_node("tools", tool_node)
    g.add_edge(START, "agent")
    g.add_conditional_edges("agent", route, {"tools": "tools", "end": END})
    g.add_edge("tools", "agent")
    return g.compile()


class VitniReplayCallback(BaseCallbackHandler):
    """Observability adapter for ANY LangChain/LangGraph agent: records LLM + tool events
    into the session's event log. Record-only (callbacks can't re-inject for replay)."""
    def __init__(self, session, *, allow_cleartext: bool = False):
        _require_langgraph()
        self.session = session
        self._pending = ("?", "")
        # SAFE BY DEFAULT: redact observed tool payloads (an observability callback still
        # must not write PHI/secrets into the signed receipt). Cleartext -> the vault.
        self.allow_cleartext = allow_cleartext
        if allow_cleartext:
            self.vault = None
        else:
            from .redact import Vault
            self.vault = Vault()

    def on_llm_end(self, response, **kwargs):
        try:
            text = response.generations[0][0].text
        except Exception:
            text = str(response)[:200]
        self.session.log.append(Kind.LLM_CALL, {"text": text, "via": "callback"})

    def on_tool_start(self, serialized, input_str, **kwargs):
        name = serialized.get("name", "?") if isinstance(serialized, dict) else "?"
        self._pending = (name, str(input_str))

    def on_tool_end(self, output, **kwargs):
        name, inp = self._pending
        result = str(output)[:200]
        idx = len(self.session.log)
        if self.allow_cleartext:
            self.session.log.append(Kind.TOOL_CALL,
                {"tool": name, "args": [inp], "decision": "OBSERVED", "result": result})
            return
        import os
        from .redact import _commit
        asalt, rsalt = os.urandom(16), os.urandom(16)
        self.session.log.append(Kind.TOOL_CALL,
            {"tool": name, "args_commit": _commit(asalt, [inp]),
             "decision": "OBSERVED", "result_commit": _commit(rsalt, result)})
        self.vault.put(idx, args_salt=asalt, args=[inp], result_salt=rsalt, result=result)
