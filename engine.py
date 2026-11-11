"""Forward-chaining inference engine with MYCIN-style certainty factors.

Facts are a dict {fact_id: certainty} where certainty is between 0 and 1.
Rules are plain data (see Rule). infer() keeps firing rules until nothing
new can be concluded, and records every firing so the UI can explain itself.
"""
from dataclasses import dataclass, field


@dataclass
class Rule:
    id: str
    if_all: list          # every one of these facts must be known
    then: str             # fact this rule concludes
    cf: float             # how much the expert trusts this rule (0..1)
    if_any: list = field(default_factory=list)  # plus at least one of these, if given
    because: str = ""     # plain-language reason, shown in the explanation tab


def combine(old, new):
    """MYCIN combination for two positive pieces of evidence for the same fact."""
    return old + new * (1 - old)


def premise_cf(rule, facts):
    """Certainty of a rule's IF part, or None if the rule can't fire."""
    if any(facts.get(f, 0) <= 0 for f in rule.if_all):
        return None
    cfs = [facts[f] for f in rule.if_all]
    if rule.if_any:
        known = [facts[f] for f in rule.if_any if facts.get(f, 0) > 0]
        if not known:
            return None
        cfs.append(max(known))  # OR = strongest supporting fact
    return min(cfs)              # AND = weakest link


def infer(facts, rules):
    """Forward chaining. Returns (all facts, trace of (rule, cf) in firing order)."""
    facts = dict(facts)
    fired, trace = set(), []
    changed = True
    while changed:                       # repeat passes until nothing new fires
        changed = False
        for rule in rules:
            if rule.id in fired:
                continue
            p = premise_cf(rule, facts)
            if p is None:
                continue
            cf = round(p * rule.cf, 3)
            facts[rule.then] = round(combine(facts.get(rule.then, 0), cf), 3)
            fired.add(rule.id)
            trace.append((rule, cf))
            changed = True
    return facts, trace


def why_not(goal, facts, rules):
    """For each rule that could conclude `goal`, list the premises that are missing."""
    out = []
    for r in rules:
        if r.then != goal:
            continue
        missing = [f for f in r.if_all if facts.get(f, 0) <= 0]
        if r.if_any and not any(facts.get(f, 0) > 0 for f in r.if_any):
            missing.append("one of: " + ", ".join(r.if_any))
        out.append((r, missing))
    return out
