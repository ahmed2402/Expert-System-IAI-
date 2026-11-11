"""Self-checks. Run: python test_engine.py"""
from engine import Rule, combine, infer, why_not
from knowledge_base import RULES, SCENARIOS, QUESTIONS, CONTEXT, ATTACKS, diagnose

# MYCIN combination
assert abs(combine(0.6, 0.5) - 0.8) < 1e-9

# chaining across two rules, AND = min, rule CF multiplies
rules = [Rule("A", ["x", "y"], "m", 0.5), Rule("B", ["m"], "goal", 0.8)]
facts, trace = infer({"x": 1.0, "y": 0.6}, rules)
assert facts["m"] == 0.3 and facts["goal"] == 0.24, facts
assert [r.id for r, _ in trace] == ["A", "B"]

# if_any = OR; nothing fires without it
r = [Rule("C", ["x"], "g", 1.0, if_any=["p", "q"])]
assert "g" not in infer({"x": 1}, r)[0]
assert infer({"x": 1, "q": 0.5}, r)[0]["g"] == 0.5

# why_not reports missing premises
assert why_not("goal", {"x": 1.0}, rules)[0][1] == ["m"]

# knowledge base sanity
assert len(RULES) >= 50, len(RULES)
assert len({r.id for r in RULES}) == len(RULES), "duplicate rule ids"
known = {f for qs in QUESTIONS.values() for f, _ in qs} | {f for f, _ in CONTEXT} | {r.then for r in RULES}
for r in RULES:
    for f in r.if_all + r.if_any:
        assert f in known, f"{r.id} uses unknown fact {f}"
for a in ATTACKS:
    assert any(r.then == a for r in RULES), f"no rule concludes {a}"

# each demo scenario diagnoses its expected attack first
for name, (inputs, expected) in SCENARIOS.items():
    attacks, severity, actions, _, _ = diagnose({f: 1.0 for f in inputs})
    assert attacks and attacks[0][0] == expected, (name, attacks[:3])
    print(f"ok  {name:38} -> {ATTACKS[expected][0]} ({attacks[0][1]:.2f}), {severity}, {len(actions)} actions")

assert diagnose({}) [0] == []
print(f"all checks passed: {len(RULES)} rules, {sum(len(q) for q in QUESTIONS.values())} questions")
