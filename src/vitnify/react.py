"""Framework-agnostic ReAct interception: the MODEL chooses which tool to call and
with what arguments (parsed from its own output), and every LLM step + tool call is
routed through the record/replay Session -- so a real, model-driven agent becomes
recordable, replayable, and certifiable with no change to the agent logic.

Small models are weak at rigid formats, so we prime each step and parse leniently
(any known tool name followed by [args], anywhere in the output). The model still
makes the meaningful choice -- which tool, which arguments; we only scaffold the syntax.

Adapts the a LangChain callback/decorator skeleton, but records full
tokens+logit_hashes+tool-result (re-injectable) rather than a truncated audit string --
that's what enables deterministic replay. A LangChain BaseCallbackHandler adapter is a
thin wrapper over `Session` (note at bottom).
"""
from __future__ import annotations
import re

REACT_SYS = (
    "You are a support agent that MUST use a tool before answering. "
    "Emit exactly one line of the form:  <tool_name>[<argument>]\n"
    "Then stop. Do not role-play the customer.\n\n"
    "Tools:\n{tools}\n"
)
_FINAL = re.compile(r"Final Answer:\s*(.+)", re.S)

def parse_action(text: str, tool_names):
    """Return {'tool','args'} | {'final':str} | None. Lenient: earliest known
    tool-name followed by [args] wins; else a Final Answer; else nothing."""
    fa = _FINAL.search(text)
    best = None
    for name in tool_names:
        m = re.search(re.escape(name) + r"\s*\[([^\]]*)\]", text)
        if m and (best is None or m.start() < best[0]):
            best = (m.start(), name, m.group(1).strip().strip('"\''))
    if best and (not fa or best[0] < fa.start()):
        _, name, arg = best
        return {"tool": name, "args": [arg] if arg else []}
    if fa:
        return {"final": fa.group(1).strip()[:120]}
    return None

def run_react(session, task: str, tools_desc: str, tool_names, max_steps=3, n_new=40):
    """Drive a model-chosen tool-use loop through the Session. Control flow is the
    model's parsed output. Returns a transcript of (role, text)."""
    base = (f"<|system|>\n{REACT_SYS.format(tools=tools_desc)}</s>\n"
            f"<|user|>\n{task}</s>\n<|assistant|>\n")
    prompt = base
    transcript = []
    for step in range(max_steps):
        prime = "" if step == 0 else "Thought: "        # nudge the format; model fills the choice
        raw = session.llm(prompt + prime, n_new=n_new)  # recorded + recomputable
        text = (prime + raw).strip()
        transcript.append(("model", text))
        act = parse_action(text, tool_names)
        if act is None or "final" in act:
            transcript.append(("final", act["final"] if act else "(no further tool call)"))
            break
        ok, obs = session.tool(act["tool"], *act["args"])   # routed through the capability wall
        observation = obs if ok else f"DENIED: agent has no capability '{act['tool']}'"
        transcript.append(("tool", f"{act['tool']}({act['args']}) -> {observation}"))
        prompt += text + f"\nObservation: {observation}\n"
    return transcript

def run_react_chat(session, task: str, tools_desc: str, tool_names, max_steps=4, n_new=64):
    """Multi-turn ReAct for real chat/instruct models (Qwen, Llama...). Uses the model's
    own chat template each turn; the model sees each tool Observation and decides the next
    action. Everything routes through the Session, so record/replay/certify is unchanged.
    Returns a transcript of (role, text)."""
    messages = [{"role": "system", "content": REACT_SYS.format(tools=tools_desc)},
                {"role": "user", "content": task}]
    transcript = []
    for _ in range(max_steps):
        prompt = session.lm.chat_prompt(messages)
        text = session.llm(prompt, n_new=n_new).strip()     # recorded + recomputable
        transcript.append(("model", text))
        act = parse_action(text, tool_names)
        if act is None or "final" in act:
            transcript.append(("final", act["final"] if act else "(no tool call)"))
            break
        ok, obs = session.tool(act["tool"], *act["args"])    # capability wall
        observation = obs if ok else f"DENIED: agent has no capability '{act['tool']}'"
        transcript.append(("tool", f"{act['tool']}({act['args']}) -> {observation}"))
        messages.append({"role": "assistant", "content": text})
        messages.append({"role": "user", "content":
                         f"Observation: {observation}\nEmit the next <tool_name>[<arg>], or 'Final Answer: ...'."})
    return transcript

# --- LangChain adapter (note) ---------------------------------------------------
# To plug into an existing LangChain/LangGraph agent: wrap the model in a Session and
# register a BaseCallbackHandler whose on_llm_end / on_tool_end forward to session.log
# (a thin LangChain callback). The difference from that
# skeleton: record full tokens+logit_hashes+tool-result (re-injectable), not a
# 1000-char audit truncation -- that is what makes the run replayable.
