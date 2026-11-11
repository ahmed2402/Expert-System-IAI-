"""CyberTriage: Streamlit front end for the cyber-incident triage expert system."""
from datetime import datetime

import streamlit as st

from engine import why_not
from knowledge_base import (ACTIONS, ATTACKS, CONTEXT, QUESTIONS, RULES, SCENARIOS,
                            diagnose, label)

st.set_page_config(page_title="CyberTriage", page_icon=":material/shield:", layout="wide")

ANSWER_CF = {"Yes": 1.0, "Not sure": 0.5}
SEV_CLASS = {"Low": "low", "Medium": "med", "High": "high", "Critical": "crit"}

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


# ------------------------------------------------------------------ state helpers
def reset():
    for key in list(st.session_state):
        if key.startswith(("q_", "c_")):
            del st.session_state[key]


def load_scenario(name):
    reset()
    for fid in SCENARIOS[name][0]:
        st.session_state[("c_" if fid.startswith("ctx_") else "q_") + fid] = (
            True if fid.startswith("ctx_") else "Yes")


def collect_answers():
    answers = {}
    for qs in QUESTIONS.values():
        for fid, _ in qs:
            value = st.session_state.get("q_" + fid)
            if value in ANSWER_CF:
                answers[fid] = ANSWER_CF[value]
    for fid, _ in CONTEXT:
        if st.session_state.get("c_" + fid):
            answers[fid] = 1.0
    return answers


def pill(severity):
    return f'<span class="pill {SEV_CLASS[severity]}">Typically {severity.lower()}</span>'


def report_markdown(answers, attacks, severity, actions, trace):
    lines = [f"# CyberTriage incident report", f"Generated {datetime.now():%d %b %Y, %H:%M}", "",
             f"**Overall severity:** {severity or 'none detected'}", "", "## What was reported"]
    lines += [f"- {label(f)}" + (" (not sure)" if cf < 1 else "") for f, cf in answers.items()]
    lines += ["", "## Likely attacks"]
    for a, cf in attacks:
        name, sev, desc, steps = ATTACKS[a]
        lines += [f"### {name}: confidence {cf:.0%}, {sev}", desc, ""]
        lines += [f"{i}. {s}" for i, s in enumerate(steps, 1)] + [""]
    if actions:
        lines += ["## Do these first"] + [f"- {a}" for a in actions] + [""]
    lines += ["## Rules that fired"] + [f"- {r.id}: {r.because} (CF {cf:.2f})" for r, cf in trace]
    return "\n".join(lines)


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.subheader("Try a demo case")
    st.caption("Each one fills in the questionnaire with a realistic incident.")
    for name in SCENARIOS:
        st.button(name, on_click=load_scenario, args=(name,), width="stretch")
    st.button("Clear all answers", on_click=reset, icon=":material/restart_alt:",
              width="stretch", type="tertiary")
    st.divider()
    st.subheader("About this incident")
    for fid, text in CONTEXT:
        st.toggle(text, key="c_" + fid)

answers = collect_answers()
attacks, severity, actions, facts, trace = diagnose(answers)
symptom_count = sum(1 for f in answers if not f.startswith("ctx_"))

# ------------------------------------------------------------------ header
st.title("CyberTriage")
st.markdown("Tell it what you're seeing on your device or accounts. It works out what's probably going on, "
            "how bad it is, and what to do first, and it shows its reasoning.")

tab_assess, tab_diag, tab_why, tab_kb = st.tabs([
    ":material/checklist: Assess",
    f":material/emergency: Diagnosis ({len(attacks)})",
    ":material/account_tree: Reasoning",
    ":material/menu_book: Knowledge base",
])

# ------------------------------------------------------------------ assess
with tab_assess:
    if attacks:
        top, cf = attacks[0]
        st.info(f"{symptom_count} signs marked. Leading suspicion: **{ATTACKS[top][0]}** "
                f"({cf:.0%} confidence). Open the Diagnosis tab for the full picture.",
                icon=":material/troubleshoot:")
    else:
        st.caption("Mark only what you've actually noticed. Leave the rest blank. "
                   "Pick *Not sure* if you half-remember something. The diagnosis updates as you go.")
    for group, qs in QUESTIONS.items():
        marked = sum(1 for fid, _ in qs if st.session_state.get("q_" + fid))
        with st.expander(f"{group}" + (f"  ·  {marked} marked" if marked else ""), expanded=marked > 0):
            for fid, text in qs:
                st.segmented_control(text, ["Yes", "Not sure"], key="q_" + fid)

# ------------------------------------------------------------------ diagnosis
with tab_diag:
    if not answers:
        st.markdown("#### Nothing to diagnose yet")
        st.write("Answer a few questions on the Assess tab, or load a demo case from the sidebar.")
    elif not attacks:
        st.markdown("#### No known attack pattern matches")
        st.write("What you described doesn't line up with any of the 15 attack profiles strongly enough "
                 f"(the cut-off is {int(0.3 * 100)}% confidence). That's good news, but stay careful:")
        st.markdown("- Update your OS, browser and antivirus.\n- Turn on two-factor authentication for email "
                    "and banking.\n- If something still feels off, ask someone technical to take a look.")
    else:
        sev_line = {"Critical": "Act now. Minutes matter here.",
                    "High": "Deal with this today.",
                    "Medium": "Fix this soon. It isn't an emergency yet.",
                    "Low": "Annoying, but not dangerous on its own."}[severity]
        st.markdown(f'<div class="sev {SEV_CLASS[severity]}"><h2>{severity} severity</h2>'
                    f'<p>{sev_line}</p></div>', unsafe_allow_html=True)

        if actions:
            st.markdown("#### Do these first")
            for a in actions:
                st.markdown(f"- {a}")

        st.markdown("#### What's probably happening")
        for i, (a, cf) in enumerate(attacks):
            name, sev, desc, steps = ATTACKS[a]
            with st.expander(f"**{name}**  ·  {cf:.0%} confidence", expanded=i == 0):
                st.markdown(f"{pill(sev)} &nbsp; {desc}", unsafe_allow_html=True)
                st.progress(cf, text=f"Certainty factor {cf:.2f}")
                st.markdown("\n".join(f"{n}. {s}" for n, s in enumerate(steps, 1)))

        st.download_button("Download incident report", report_markdown(answers, attacks, severity, actions, trace),
                           file_name="cybertriage_report.md", icon=":material/download:")

# ------------------------------------------------------------------ reasoning
with tab_why:
    if not trace:
        st.write("No rules have fired yet. Once you answer some questions, this tab shows each "
                 "step of the system's reasoning.")
    else:
        st.markdown("#### The reasoning chain")
        st.caption("Forward chaining: facts you gave on the left, everything the rules concluded to the right.")
        derived = list(dict.fromkeys(r.then for r, _ in trace))  # firing order, no duplicates
        layers = [
            ("You reported", [f for f in answers]),
            ("Which suggests", [f for f in derived if f not in ATTACKS and not f.startswith(("sev_", "act_"))]),
            ("Likely attacks", [a for a, _ in attacks]),
            ("So the system adds", [f for f in derived if f.startswith(("sev_", "act_"))]),
        ]
        for col, (title, items) in zip(st.columns(4), layers):
            with col:
                st.markdown(f"**{title}**")
                for f in items:
                    st.markdown(f"{label(f)} `{facts[f]:.2f}`")
                if not items:
                    st.caption("nothing")

        st.markdown("#### Every rule that fired, in order")
        for r, cf in trace:
            cond = " AND ".join(label(f) for f in r.if_all)
            if r.if_any:
                cond += (" AND " if cond else "") + "(" + " OR ".join(label(f) for f in r.if_any) + ")"
            st.markdown(f'<span class="rid">{r.id}</span> &nbsp;IF {cond} THEN <b>{label(r.then)}</b> '
                        f'&nbsp;·&nbsp; CF {cf:.2f}<br><small>{r.because}</small>', unsafe_allow_html=True)

    st.markdown("#### Why not something else?")
    others = [a for a in ATTACKS if a not in dict(attacks)]
    pick = st.selectbox("Pick an attack the system didn't report", others,
                        format_func=lambda a: ATTACKS[a][0], index=None, placeholder="Choose an attack")
    if pick:
        for r, missing in why_not(pick, facts, RULES):
            if missing:
                st.markdown(f'<span class="rid">{r.id}</span> &nbsp;needs: ' +
                            ", ".join(label(m) if not m.startswith("one of") else
                                      "one of " + " / ".join(label(x) for x in m[8:].split(", "))
                                      for m in missing), unsafe_allow_html=True)
            else:
                st.markdown(f'<span class="rid">{r.id}</span> &nbsp;fired, but the total confidence '
                            f'stayed under the 30% cut-off.', unsafe_allow_html=True)

# ------------------------------------------------------------------ knowledge base
with tab_kb:
    st.markdown(f"#### {len(RULES)} rules, {sum(len(q) for q in QUESTIONS.values())} questions, "
                f"{len(ATTACKS)} attack profiles")
    st.caption("Layer 1 turns symptoms into indicators. Layer 2 turns indicators into attacks. "
               "Layer 3 uses the situation to set severity and add urgent actions.")
    rows = []
    for r in RULES:
        n = int(r.id[1:])
        cond = " AND ".join(r.if_all)
        if r.if_any:
            cond += (" AND " if cond else "") + "ANY(" + ", ".join(r.if_any) + ")"
        rows.append({"Rule": r.id, "Layer": 1 if n <= 21 else 2 if n <= 52 else 3,
                     "IF": cond, "THEN": r.then, "CF": r.cf, "Why": r.because})
    st.dataframe(rows, hide_index=True, width="stretch", height=560)
