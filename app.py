"""CyberTriage: Streamlit front end for the cyber-incident triage expert system.

A three-step wizard: pick where the trouble is, answer only those questions,
read the diagnosis. All reasoning happens in engine.py / knowledge_base.py.
"""
from datetime import datetime

import streamlit as st
from fpdf import FPDF

from engine import why_not
from knowledge_base import (ATTACKS, CONTEXT, QUESTIONS, RULES, SCENARIOS, DIAGNOSIS_THRESHOLD,
                            diagnose, label)

st.set_page_config(page_title="CyberTriage", page_icon=":material/shield:", layout="centered")

ANSWER_CF = {"Yes": 1.0, "Not sure": 0.5}
SEV_CLASS = {"Low": "low", "Medium": "med", "High": "high", "Critical": "crit"}
SEV_LINE = {"Critical": "Act now. Minutes matter here.", "High": "Deal with this today.",
            "Medium": "Fix this soon. It isn't an emergency yet.", "Low": "Annoying, but not dangerous on its own."}
SEV_RGB = {"Low": (46, 107, 71), "Medium": (242, 179, 61), "High": (194, 65, 12), "Critical": (159, 18, 57)}

st.html("""
<style>
:root { --low:#2E6B47; --med:#F2B33D; --high:#C2410C; --crit:#9F1239; }
html, body, [data-testid="stAppViewContainer"] { font-variant-numeric: tabular-nums; }
::selection { background:#CFE3E1; color:#0E1B1A; }
.sev { border-radius:10px; padding:1.1rem 1.4rem; margin:.25rem 0 1.25rem; color:#fff;
       box-shadow:0 6px 18px -8px rgba(0,0,0,.35); }
.sev h2 { margin:0; padding:0; font-size:1.6rem; color:inherit; }
.sev p { margin:.2rem 0 0; opacity:.92; }
.sev.low { background:var(--low); } .sev.med { background:var(--med); color:#2B1D00; }
.sev.high { background:var(--high); } .sev.crit { background:var(--crit); }
.pill { display:inline-block; font-size:.78rem; font-weight:600; padding:.1rem .55rem;
        border-radius:999px; color:#fff; vertical-align:middle; }
.pill.low { background:var(--low); } .pill.med { background:var(--med); color:#2B1D00; }
.pill.high { background:var(--high); } .pill.crit { background:var(--crit); }
.rid { font-family:ui-monospace,Consolas,monospace; font-size:.85rem; color:#0F5E5A; font-weight:600; }
</style>
""")

# ------------------------------------------------------------------ state
# Answers live in plain session-state dicts (not widget keys), so they survive
# moving between steps, when the widgets themselves aren't on screen.
ss = st.session_state
ss.setdefault("step", 1)
ss.setdefault("ans", {})      # fact_id -> "Yes" / "Not sure"
ss.setdefault("ctx", set())   # context fact_ids that are on
ss.setdefault("groups", [])   # question groups the user picked


def clear_widgets():
    for key in [k for k in ss if k.startswith(("w_", "c_")) or k == "groups_w"]:
        del ss[key]


def reset():
    ss.step, ss.ans, ss.ctx, ss.groups = 1, {}, set(), []
    clear_widgets()


def load_scenario(name):
    reset()
    facts = SCENARIOS[name][0]
    ss.ans = {f: "Yes" for f in facts if not f.startswith("ctx_")}
    ss.ctx = {f for f in facts if f.startswith("ctx_")}
    ss.groups = [g for g, qs in QUESTIONS.items() if any(f in ss.ans for f, _ in qs)]
    ss.step = 3


def go(step):
    ss.step = step


def save_answer(fid):
    value = ss["w_" + fid]
    if value:
        ss.ans[fid] = value
    else:
        ss.ans.pop(fid, None)


def save_ctx(fid):
    (ss.ctx.add if ss["c_" + fid] else ss.ctx.discard)(fid)


def save_groups():
    ss.groups = ss.groups_w or []


def current_answers():
    answers = {f: ANSWER_CF[v] for f, v in ss.ans.items()}
    answers.update({f: 1.0 for f in ss.ctx})
    return answers


def pill(severity):
    return f'<span class="pill {SEV_CLASS[severity]}">Typically {severity.lower()}</span>'


def rule_text(r, facts=None):
    """IF ... THEN ... in plain words. Given facts, only the OR-options that matched are shown."""
    cond = " AND ".join(label(f) for f in r.if_all)
    options = [f for f in r.if_any if facts is None or facts.get(f, 0) > 0]
    if options:
        cond += (" AND " if cond else "") + "(" + " OR ".join(label(f) for f in options) + ")"
    return f"IF {cond} THEN {label(r.then)}"


# ------------------------------------------------------------------ PDF report
def build_pdf(answers, attacks, severity, actions, facts, trace):
    pdf = FPDF()
    pdf.set_auto_page_break(True, margin=15)
    pdf.add_page()
    w = pdf.epw

    def heading(text, size=13):
        pdf.ln(4)
        pdf.set_font("Helvetica", "B", size)
        pdf.multi_cell(w, 7, text)
        pdf.set_font("Helvetica", "", 10.5)

    def para(text, indent=0):
        pdf.set_x(pdf.l_margin + indent)
        pdf.multi_cell(w - indent, 5.5, text)

    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(w, 10, "CyberTriage incident report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(90, 90, 90)
    pdf.cell(w, 6, f"Generated {datetime.now():%d %b %Y, %H:%M}", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(0, 0, 0)
    pdf.ln(3)

    if severity:
        pdf.set_fill_color(*SEV_RGB[severity])
        pdf.set_text_color(*((43, 29, 0) if severity == "Medium" else (255, 255, 255)))
        pdf.set_font("Helvetica", "B", 15)
        pdf.cell(w, 12, f"  {severity} severity: {SEV_LINE[severity]}", fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(0, 0, 0)
    else:
        heading("No known attack pattern matched.")

    if actions:
        heading("Do these first")
        for a in actions:
            para(f"-  {a}", 3)

    if attacks:
        heading("What's probably happening")
    for a, cf in attacks:
        name, sev, desc, steps = ATTACKS[a]
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 11.5)
        pdf.multi_cell(w, 6.5, f"{name}  ({cf:.0%} confidence, typically {sev.lower()})")
        pdf.set_font("Helvetica", "", 10.5)
        para(desc)
        for n, s in enumerate(steps, 1):
            para(f"{n}.  {s}", 3)

    heading("What you reported")
    for f, cf in answers.items():
        para(f"-  {label(f)}" + ("  (not sure)" if cf < 1 else ""), 3)

    if trace:
        heading("How the system reached this")
        pdf.set_font("Helvetica", "", 9.5)
        for r, cf in trace:
            para(f"{r.id}  {rule_text(r, facts)}  [CF {cf:.2f}]")
    return bytes(pdf.output())


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.subheader("Try a demo case")
    st.caption("Fills in a realistic incident and jumps straight to the result.")
    for name in SCENARIOS:
        st.button(name, on_click=load_scenario, args=(name,), width="stretch")

# ------------------------------------------------------------------ header
st.title("CyberTriage")
st.markdown("Something odd going on with your device or accounts? Answer a few questions and "
            "CyberTriage will tell you what's probably happening, how serious it is, and what to do first.")
st.caption(f"Step {ss.step} of 3")

# ------------------------------------------------------------------ step 1
if ss.step == 1:
    st.subheader("Where's the trouble?")
    st.pills("Pick every area where something seems wrong.", list(QUESTIONS), selection_mode="multi",
             default=ss.groups, key="groups_w", on_change=save_groups)
    st.markdown("**A bit about your situation**")
    for fid, text in CONTEXT:
        st.toggle(text, value=fid in ss.ctx, key="c_" + fid, on_change=save_ctx, args=(fid,))
    st.button("Next", type="primary", icon=":material/arrow_forward:", disabled=not ss.groups,
              on_click=go, args=(2,))

# ------------------------------------------------------------------ step 2
elif ss.step == 2:
    st.subheader("What have you noticed?")
    st.caption("Mark only what you've actually seen. Leave the rest blank, and pick *Not sure* if you half-remember.")
    for group in ss.groups:
        st.markdown(f"**{group}**")
        for fid, text in QUESTIONS[group]:
            st.segmented_control(text, ["Yes", "Not sure"], default=ss.ans.get(fid), key="w_" + fid,
                                 on_change=save_answer, args=(fid,))
    attacks = diagnose(current_answers())[0]
    if attacks:
        st.info(f"Leading suspicion so far: **{ATTACKS[attacks[0][0]][0]}**", icon=":material/troubleshoot:")
    left, right = st.columns(2)
    left.button("Back", icon=":material/arrow_back:", on_click=go, args=(1,), width="stretch")
    right.button("See diagnosis", type="primary", icon=":material/arrow_forward:", disabled=not ss.ans,
                 on_click=go, args=(3,), width="stretch")

# ------------------------------------------------------------------ step 3
else:
    answers = current_answers()
    attacks, severity, actions, facts, trace = diagnose(answers)

    if not attacks:
        st.subheader("No known attack pattern matches")
        st.write("What you described doesn't match any of the 15 attack profiles strongly enough. "
                 "That's good news, but stay careful:")
        st.markdown("- Update your OS, browser and antivirus.\n- Turn on two-factor authentication for email "
                    "and banking.\n- If something still feels off, ask someone technical to take a look.")
    else:
        st.html(f'<div class="sev {SEV_CLASS[severity]}"><h2>{severity} severity</h2>'
                f'<p>{SEV_LINE[severity]}</p></div>')
        if actions:
            st.subheader("Do these first")
            st.markdown("\n".join(f"- {a}" for a in actions))
        st.subheader("What's probably happening")
        for i, (a, cf) in enumerate(attacks):
            name, sev, desc, steps = ATTACKS[a]
            with st.expander(f"**{name}**  ·  {cf:.0%} confidence", expanded=i == 0):
                st.markdown(f"{pill(sev)} &nbsp; {desc}", unsafe_allow_html=True)
                st.progress(cf, text=f"Certainty factor {cf:.2f}")
                st.markdown("\n".join(f"{n}. {s}" for n, s in enumerate(steps, 1)))

    left, right = st.columns(2)
    left.download_button("Download PDF report", build_pdf(answers, attacks, severity, actions, facts, trace),
                         file_name="CyberTriage_incident_report.pdf", mime="application/pdf",
                         icon=":material/picture_as_pdf:", type="primary", width="stretch")
    right.button("Start over", icon=":material/restart_alt:", on_click=reset, width="stretch")
    st.button("Change my answers", icon=":material/edit:", on_click=go, args=(2,), type="tertiary")

    st.divider()
    st.subheader("Under the hood")

    with st.expander("How it reached this answer"):
        st.caption("Forward chaining: it starts from what you reported and keeps applying rules until "
                   "nothing new can be concluded. CF is the certainty factor of each conclusion.")
        for r, cf in trace:
            st.markdown(f'<span class="rid">{r.id}</span> &nbsp;{rule_text(r, facts)} &nbsp;·&nbsp; CF {cf:.2f}'
                        f'<br><small>{r.because}</small>', unsafe_allow_html=True)

    with st.expander("Why not something else?"):
        others = [a for a in ATTACKS if a not in dict(attacks)]
        pick = st.selectbox("Pick an attack the system didn't report", others,
                            format_func=lambda a: ATTACKS[a][0], index=None, placeholder="Choose an attack")
        if pick:
            for r, missing in why_not(pick, facts, RULES):
                if missing:
                    need = [label(m) if not m.startswith("one of") else
                            "one of " + " / ".join(label(x) for x in m[8:].split(", ")) for m in missing]
                    st.markdown(f'<span class="rid">{r.id}</span> &nbsp;needs: ' + "; ".join(need),
                                unsafe_allow_html=True)
                else:
                    st.markdown(f'<span class="rid">{r.id}</span> &nbsp;fired, but the total confidence stayed '
                                f'under the {DIAGNOSIS_THRESHOLD:.0%} cut-off.', unsafe_allow_html=True)

    with st.expander(f"The knowledge base: all {len(RULES)} rules"):
        st.caption("Layer 1 turns symptoms into warning signs. Layer 2 turns warning signs into attacks. "
                   "Layer 3 uses your situation to set severity and add urgent actions.")
        rows = []
        for r in RULES:
            n = int(r.id[1:])
            cond = " AND ".join(r.if_all)
            if r.if_any:
                cond += (" AND " if cond else "") + "ANY(" + ", ".join(r.if_any) + ")"
            rows.append({"Rule": r.id, "Layer": 1 if n <= 21 else 2 if n <= 52 else 3,
                         "IF": cond, "THEN": r.then, "CF": r.cf})
        st.dataframe(rows, hide_index=True, width="stretch", height=420)
