# CyberTriage

A rule-based expert system that triages cyber incidents. You describe what you're seeing on your device or accounts, and it tells you which attack is most likely, how serious it is, what to do first, and which rules led it there.

Built for the *Introduction to AI* CCP. Live app: **https://cybertriage.streamlit.app/**

## How it works

- `engine.py`: a forward-chaining inference engine written from scratch. Rules carry MYCIN-style certainty factors. An AND takes the weakest premise, an OR takes the strongest, and several rules backing the same conclusion combine as `cf1 + cf2 * (1 - cf1)`. Every firing is logged so the app can explain itself.
- `knowledge_base.py`: 51 questions, 67 rules in three layers (symptoms → indicators → attacks → severity and actions), and 15 attack profiles with response steps.
- `app.py`: the Streamlit interface. It walks you through three steps (pick where the trouble is, answer only those questions, read the diagnosis) and lets you download the result as a PDF report. Under the result you can open the full reasoning trace, a "why not X?" check and all 67 rules. The sidebar has five one-click demo cases.
- `test_engine.py`: self-checks for the engine and for each demo case.

## Run it locally

```
pip install -r requirements.txt
python test_engine.py
streamlit run app.py
```
