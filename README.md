# ContextGuard – Context-Aware Data Privacy (DevHost 2026, PS 2.2)
Team **Code Catalysts** – Yenepoya Institute of Technology, Moodbidri

ContextGuard sits between workplace text and an AI tool. It detects sensitive entities (Aadhaar, PAN, IFSC,
phone, email, salary, person names), scores each one in context (surrounding words, user role, destination),
then allows, masks, redacts or blocks, and logs every decision with its reason.

## Run
    pip install -r requirements.txt
    streamlit run app.py

## Demo idea
Load "Offer details to vendor", then change role and destination and scan again:
HR Manager + Internal tool -> allowed; Employee + Internal tool -> redacted/masked;
any role + External AI tool -> redacted.

## Files
- `contextguard.py` – detection, context scoring, policy, sanitising
- `app.py` – Streamlit UI and audit log

## Limitations
Rule-based context scoring in this MVP; planned upgrade is a trained classifier on labelled workplace text.
