"""ed25519 execution certificate: signed with a private key, verified by ANYONE
with only the certificate itself (the public key is embedded) -- no shared secret.
"""
import os, sys, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "vendored"))
from vitnify.events import EventLog, Kind
from vitnify.capability import Broker
from vitnify.certificate import issue_certificate, verify_certificate, gen_ed25519

SECRET = "patient_ssn=123-45-6789"
tools = {"read_public": lambda x: f"public::{x}", "read_secret": lambda: SECRET,
         "send_external": lambda d, x: "SENT"}
PROG = hashlib.blake2b(b"agent", digest_size=16).hexdigest()

def run():
    log = EventLog(); br = Broker({"read_public"}, tools, log)
    br.call("read_public", "ticket#7"); br.call("read_secret"); br.call("send_external", "attacker", SECRET)
    return log

priv, pubhex = gen_ed25519()
log = run()
cert, _ = issue_certificate(PROG, {"read_public"}, log, priv=priv)   # signed with PRIVATE key
print(f"alg={cert.sig_alg}  pubkey={cert.pubkey[:24]}…  sig={cert.sig[:24]}…")

v = verify_certificate(cert, log)                                    # verified with NO secret
print(f"verify (no shared secret):            ok={v['ok']}  sig_valid={v['sig_valid']}")

for e in log.events:                                                 # tamper a blocked call
    if e.payload.get("tool") == "send_external":
        e.payload["decision"] = "ALLOW"; e.payload["result"] = "SENT"
v2 = verify_certificate(cert, log)
print(f"verify after DENY->ALLOW tamper:      ok={v2['ok']}  (root_matches={v2['root_matches']})")

log2 = run(); cert2, _ = issue_certificate(PROG, {"read_public"}, log2, priv=priv)
cert2.sig = cert2.sig[:-2] + ("00" if cert2.sig[-2:] != "00" else "01")   # corrupt the signature
v3 = verify_certificate(cert2, log2)
print(f"verify with a forged/corrupted sig:   ok={v3['ok']}  sig_valid={v3['sig_valid']}")

ok = v["ok"] and not v2["ok"] and not v3["ok"]
print("\nRESULT:", "ed25519 CERTIFICATE OK (self-verifiable, tamper- & forgery-evident)" if ok else "PROBLEM")
