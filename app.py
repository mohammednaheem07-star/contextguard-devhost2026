import html, datetime
import pandas as pd
import streamlit as st
from contextguard import process, overall_action, ROLES, DESTINATIONS

st.set_page_config(page_title="ContextGuard", page_icon="🛡️", layout="wide")
st.title("🛡️ ContextGuard")
st.caption("Context-aware privacy gateway for AI workflows  |  Team Code Catalysts  |  DevHost 2026, PS 2.2")

SAMPLES = {
    "Offer details to vendor": "Summarise for the vendor: Priya Nair's offer is ₹18 LPA, call 98765 43210.",
    "Public policy FAQ (harmless)": "Our public salary policy FAQ explains how increments work.",
    "Government IDs": "Customer PAN is ABCDE1234F and Aadhaar is 1234 5678 9012, please verify.",
    "Confidential appraisal": "Mail ramesh.k@acme.com about his confidential appraisal and hike.",
    "Press release (public name)": "The press release announced Rahul Mehta as the new CEO.",
}
COLORS = {"ALLOW": "#c8e6c9", "MASK": "#ffe0b2", "REDACT": "#ffcdd2"}

if "log" not in st.session_state:
    st.session_state.log = []

with st.sidebar:
    st.header("Context")
    role = st.selectbox("User role", ROLES)
    dest = st.selectbox("Where is this text going?", DESTINATIONS)
    st.markdown("Change the role or destination and run the **same text** again.")

sample = st.selectbox("Load a sample", ["(type your own)"] + list(SAMPLES))
default = SAMPLES.get(sample, "")
text = st.text_area("Text to send to the AI", value=default, height=130)

if st.button("Scan with ContextGuard", type="primary") and text.strip():
    ents, sanitised, blocked = process(text, role, dest)
    action = overall_action(ents, blocked)

    # highlighted original
    parts, pos = [], 0
    for e in ents:
        parts.append(html.escape(text[pos:e.start]))
        parts.append(f"<mark style='background:{COLORS[e.action]};padding:2px 4px;border-radius:4px'>"
                     f"{html.escape(e.text)} <small>({e.type})</small></mark>")
        pos = e.end
    parts.append(html.escape(text[pos:]))

    badge = {"ALLOW": "🟢 ALLOWED", "MASK": "🟠 MASKED", "REDACT": "🔴 REDACTED", "BLOCK": "⛔ BLOCKED"}[action]
    st.subheader(f"Decision: {badge}")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Original (detected spans highlighted)**")
        st.markdown("".join(parts), unsafe_allow_html=True)
    with c2:
        st.markdown("**Sanitised text sent to the AI**")
        st.code(sanitised, language=None)

    if ents:
        st.markdown("**Why? (explainable decisions)**")
        st.dataframe(pd.DataFrame([{"Entity": e.type, "Text": e.text, "Risk (0-1)": e.risk,
                                    "Action": e.action, "Reason": e.reason} for e in ents]),
                     use_container_width=True, hide_index=True)
    else:
        st.info("No sensitive entities detected, so the text is passed through unchanged.")

    st.session_state.log.append({"Time": datetime.datetime.now().strftime("%H:%M:%S"), "Role": role,
        "Destination": dest, "Entities": ", ".join(e.type for e in ents) or "-", "Decision": action})

st.divider()
st.subheader("Audit log")
if st.session_state.log:
    df = pd.DataFrame(st.session_state.log)
    st.dataframe(df, use_container_width=True, hide_index=True)
    st.download_button("Download audit log (CSV)", df.to_csv(index=False), "audit_log.csv", "text/csv")
else:
    st.caption("Decisions will appear here after you scan some text.")
