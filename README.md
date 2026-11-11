# CyberTriage

A rule-based expert system that triages cyber incidents. You describe what you're seeing on your device or accounts, and it tells you which attack is most likely, how serious it is, what to do first, and which rules led it there.

Built for the *Introduction to AI* CCP. Live app: **(link added after deployment)**

## How it works

- `engine.py`: a forward-chaining inference engine written from scratch. Rules carry MYCIN-style certainty factors. An AND takes the weakest premise, an OR takes the strongest, and several rules backing the same conclusion combine as `cf1 + cf2 * (1 - cf1)`. Every firing is logged so the app can explain itself.
- `knowledge_base.py`: 51 questions, 67 rules in three layers (symptoms → indicators → attacks → severity and actions), and 15 attack profiles with response steps.
- `app.py`: the Streamlit interface, with Assess, Diagnosis, Reasoning and Knowledge base tabs, plus five one-click demo cases.
- `test_engine.py`: self-checks for the engine and for each demo case.

## Run it locally

```
pip install -r requirements.txt
python test_engine.py
streamlit run app.py
```
