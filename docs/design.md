# CyberTriage: Cyber-Incident Triage Expert System — Design & Plan

## Intent
CCP for *Introduction to AI*. A rule-based expert system that asks a non-expert
what they're seeing on their device or accounts and returns:
the likely attack type(s), a confidence score, a severity level, ordered
containment steps, and **the exact chain of rules that led there**.

## Requirements (from the course)
- Python, **≥ 50 conditions/rules**, unique niche → cyber-incident triage.
- UI in **Streamlit only**, deployed live (WAN) → Streamlit Community Cloud from the user's GitHub.
- Submission: project zip + PDF code explanation with the live link.

## Goals
- A forward-chaining inference engine written from scratch, with no expert-system library, so every line can be explained in the viva.
- **MYCIN-style certainty factors** (CF) on rules and conclusions.
- An **explanation facility** showing which rules fired, in order, and why (IF … THEN …).
- A knowledge-base browser that lists every rule, so the 50+ count is visible.
- One-click **demo scenarios** for a reliable live demo in the viva.

## Non-goals / anti-goals
- No ML or LLM: it must be a classic, explainable expert system.
- No login, no database, no persistence: the app is stateless.
- Anti-goal: rules buried in if/else spaghetti. Rules are **data**, so they're easy to count and explain.

## Architecture (4 code files)
| File | Role |
|---|---|
| `engine.py` | `Rule` dataclass + `infer(facts)` forward chaining, CF combination, trace log |
| `knowledge_base.py` | Questions (UI input → fact ids) + ~60 rules + attack info (description, severity, actions) |
| `app.py` | Streamlit UI |
| `test_engine.py` | Plain `assert` checks: the engine runs, and each demo scenario gives its expected attack |

Plus `requirements.txt` (`streamlit`), `README.md`, `report/CyberTriage_Report.pdf`.

### Inference
- Facts: `dict[fact_id → CF]`. A ticked symptom has CF 1.0; "not sure" gives 0.5.
- Rule: `id, if_all=[facts], if_any=[facts], then=fact, cf, explanation`.
- Fires when every `if_all` fact is present and at least one `if_any` fact is (when given).
  Rule CF = `min(premise CFs) × rule.cf`.
- Same conclusion from several rules: `CF = cf1 + cf2·(1 − cf1)` (MYCIN combination).
- Loop until no rule adds or raises a fact (each rule fires at most once). Every firing is logged to the trace.

### Knowledge-base layers (three levels of chaining show off forward chaining)
1. **Symptoms → indicators**, e.g. `files_unreadable + ransom_note → files_encrypted`.
2. **Indicators → attack types** (~15): Ransomware, Phishing, Credential Theft / Account Takeover,
   Spyware/Keylogger, Cryptojacking, Botnet, Adware/PUP, Trojan/Fake App, SIM Swap,
   Social-Media Hijack, Tech-Support Scam, MITM / Rogue Wi-Fi, USB-borne Malware,
   Data Breach Exposure, Insider Misuse.
3. **Attack + context → severity & response**, e.g. `ransomware + business_device → CRITICAL`,
   `banking_involved → contact bank immediately`.

### UI (Streamlit)
- **Sidebar:** demo-scenario buttons, a reset button, and context (personal/business device, OS, banking involved).
- **Tab 1, Assessment:** symptom questions grouped in expanders (Email & Messages, Files, Device Performance,
  Network, Accounts & Logins, Phone/SIM, Browser), using Yes / Not sure answers.
- **Tab 2, Diagnosis:** ranked attack cards with a CF bar, a severity badge (colour), a description, and numbered response steps.
  A **download incident report** button (Markdown/txt).
- **Tab 3, Explanation:** the fired-rule trace in order (`R12: IF a AND b THEN c (CF 0.8)`), plus a "why not X?" picker that
  shows which conditions an attack was missing.
- **Tab 4, Knowledge Base:** a table of all rules, with the rule count shown.

## Delivery batches
1. **Engine:** `engine.py` + engine asserts in `test_engine.py`.
2. **Knowledge base:** questions, ~60 rules, attack info, and 5 demo scenarios with an assert per scenario.
3. **UI:** `app.py` with all 4 tabs; run locally and check it.
4. **Deploy:** git commit, push to the user's GitHub (public repo), deploy on Streamlit Cloud and get the link.
   *(The user confirms before the push; the user does the Streamlit Cloud sign-in.)*
5. **Submission:** PDF code explanation (architecture, engine walkthrough, rule table, screenshots, live link)
   + zip of the project.

## Working style (user's request)
- **ponytail**: lean code, few files, no over-engineering (batches 1–4).
- **impeccable**: UI/UX design pass on `app.py` (batch 3).
- **humanizer**: all UI text, attack descriptions and the PDF report read naturally (batches 2, 3, 5).

## My calls (check these)
- The project name is "CyberTriage".
- Inputs are Yes / Not sure only. "No" is the default (unticked), so the UI stays short.
- The incident report download is plain Markdown, not PDF. No extra dependency is needed.
- The PDF report is generated with `fpdf2` from a script kept out of the app's requirements.
- The user adds their name/roll number to the PDF.
