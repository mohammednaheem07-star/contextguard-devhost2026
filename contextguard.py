"""ContextGuard core: detect -> score in context -> decide -> sanitise."""
import re
from dataclasses import dataclass

# ---------- 1. DETECTION ----------
PATTERNS = {
    "AADHAAR": re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"),
    "PAN": re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
    "IFSC": re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
    "EMAIL": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),
    "PHONE": re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"),
    "SALARY": re.compile(
        r"(?:₹|Rs\.?|INR)\s?\d[\d,]*(?:\.\d+)?\s?(?:LPA|lakhs?|lacs?|crores?|cr|k)?\b"
        r"|\b\d+(?:\.\d+)?\s?(?:LPA|lakhs? per annum)\b", re.I),
}
TITLE_NAME = re.compile(r"\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?")
TWO_CAPS = re.compile(r"\b[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}\b")
NAME_CUE = re.compile(
    r"\b([A-Z][a-z]{2,})(?='s\b|\s+(?:earns|earned|joined|resigned|was|is|has|got|will|salary|package|offer))")
NOT_NAMES = {"The","This","That","Our","Send","Please","Summarise","Summarize","Share","We","Team",
             "Human","Resources","Data","Privacy","New","Project","Hello","Dear","Thanks","Regards",
             "Annual","Press","Release","Company","Policy","Office","Board","Meeting","Customer","Bank"}

try:  # optional: better names if spaCy model is installed
    import spacy
    _NLP = spacy.load("en_core_web_sm")
except Exception:
    _NLP = None

@dataclass
class Entity:
    type: str
    text: str
    start: int
    end: int
    risk: float = 0.0
    action: str = "ALLOW"
    reason: str = ""

def _overlaps(a, b):
    return a.start < b.end and b.start < a.end

def detect(text):
    ents = []
    for etype, pat in PATTERNS.items():
        for m in pat.finditer(text):
            ents.append(Entity(etype, m.group(), m.start(), m.end()))
    # drop Aadhaar-looking matches that are really phone numbers/salaries
    ents = [e for e in ents if not (e.type == "AADHAAR" and any(
        o.type in ("PHONE", "SALARY") and _overlaps(e, o) for o in ents))]
    names = []
    if _NLP:
        for ent in _NLP(text).ents:
            if ent.label_ == "PERSON":
                names.append(Entity("PERSON", ent.text, ent.start_char, ent.end_char))
    else:
        for m in TITLE_NAME.finditer(text):
            names.append(Entity("PERSON", m.group(), m.start(), m.end()))
        for m in TWO_CAPS.finditer(text):
            w = m.group().split()
            if not (set(w) & NOT_NAMES):
                names.append(Entity("PERSON", m.group(), m.start(), m.end()))
        for m in NAME_CUE.finditer(text):
            if m.group(1) not in NOT_NAMES:
                names.append(Entity("PERSON", m.group(1), m.start(1), m.end(1)))
    for n in names:
        if not any(_overlaps(n, e) for e in ents):
            ents.append(n)
    # drop single-name entities already covered by a longer name
    ents.sort(key=lambda e: (e.start, -(e.end - e.start)))
    out = []
    for e in ents:
        if not any(_overlaps(e, o) for o in out):
            out.append(e)
    return out

# ---------- 2. CONTEXT SCORING ----------
BASE_RISK = {"AADHAAR": 0.95, "PAN": 0.95, "IFSC": 0.6, "EMAIL": 0.45, "PHONE": 0.5,
             "SALARY": 0.55, "PERSON": 0.25}
CATEGORY = {"AADHAAR": "ID", "PAN": "ID", "IFSC": "FINANCE", "EMAIL": "CONTACT",
            "PHONE": "CONTACT", "SALARY": "COMPENSATION", "PERSON": "IDENTITY"}
SENSITIVE_CUES = ["offer", "package", "ctc", "salary of", "appraisal", "termination", "resign",
                  "confidential", "internal", "diagnos", "medical", "password", "bank account",
                  "layoff", "performance review", "disciplinary", "payroll", "earns", "hike"]
PUBLIC_CUES = ["public", "press release", "announced", "published", "faq", "policy", "website",
               "on linkedin", "annual report", "general", "guideline"]

def score_context(text, e, destination):
    lo, hi = max(0, e.start - 70), min(len(text), e.end + 70)
    window = text[lo:hi].lower()
    risk = BASE_RISK[e.type]
    notes = []
    s_hits = [c for c in SENSITIVE_CUES if c in window]
    p_hits = [c for c in PUBLIC_CUES if c in window]
    if s_hits:
        risk += min(0.3, 0.15 * len(s_hits)); notes.append("sensitive context: " + ", ".join(s_hits[:2]))
    if p_hits and e.type in ("PERSON", "SALARY", "EMAIL"):
        risk -= 0.3; notes.append("public context: " + ", ".join(p_hits[:2]))
    if destination == "External AI tool":
        risk += 0.2; notes.append("leaves the organisation")
    e.risk = round(max(0.0, min(1.0, risk)), 2)
    e.reason = "; ".join(notes) or "no special context"
    return e

# ---------- 3. POLICY ----------
ROLE_ACCESS = {  # which categories each role may see
    "HR Manager": {"IDENTITY", "COMPENSATION", "CONTACT", "ID"},
    "Finance Officer": {"IDENTITY", "COMPENSATION", "FINANCE", "CONTACT"},
    "Team Lead": {"IDENTITY", "CONTACT"},
    "Employee": {"IDENTITY"},
    "Intern": {"IDENTITY"},
}
ROLES = list(ROLE_ACCESS)
DESTINATIONS = ["Internal tool", "External AI tool"]

def decide(e, role, destination):
    authorised = CATEGORY[e.type] in ROLE_ACCESS[role]
    if e.risk < 0.5:
        e.action = "ALLOW"; e.reason += " | low risk"
    elif destination == "Internal tool" and authorised:
        e.action = "ALLOW"; e.reason += f" | {role} is authorised for {CATEGORY[e.type].lower()} data"
    elif destination == "Internal tool":
        e.action = "MASK" if e.type in ("PHONE", "EMAIL", "AADHAAR", "PAN") else "REDACT"
        e.reason += f" | {role} not authorised for {CATEGORY[e.type].lower()} data"
    else:
        e.action = "REDACT"; e.reason += " | external destination, risk above threshold"
    return e

# ---------- 4. SANITISE ----------
def _mask(s):
    keep = s[-4:] if len(s) > 4 else ""
    return "X" * (len(s) - len(keep)) + keep

def process(text, role, destination):
    ents = [decide(score_context(text, e, destination), role, destination) for e in detect(text)]
    blocked = destination == "External AI tool" and any(
        e.type in ("AADHAAR", "PAN") and e.action != "ALLOW" for e in ents)
    counters, tokens = {}, {}
    out, pos = [], 0
    for e in ents:
        out.append(text[pos:e.start])
        if e.action == "ALLOW":
            out.append(e.text)
        elif e.action == "MASK":
            out.append(_mask(e.text))
        else:
            key = (e.type, e.text.lower())
            if key not in tokens:
                counters[e.type] = counters.get(e.type, 0) + 1
                tokens[key] = f"[{e.type}_{counters[e.type]}]"
            out.append(tokens[key])
        pos = e.end
    out.append(text[pos:])
    sanitised = "".join(out)
    if blocked:
        sanitised = "[BLOCKED: message contains government ID numbers and cannot be sent to an external AI tool]"
    return ents, sanitised, blocked

def overall_action(ents, blocked):
    if blocked: return "BLOCK"
    acts = {e.action for e in ents}
    for a in ("REDACT", "MASK"):
        if a in acts: return a
    return "ALLOW"
