"""Step 3 - gold set: double annotation (NVD/CNA analyst CWE -> class, vs LLM) + adjudication of disagreements.

    python -m cvescope.annotate        # creates data/gold/gold.csv once, then only reports agreement
Disagreements get an empty gold_class: a human fills it (and adjudication_note) following
docs/annotation_guidelines.md. The file is never overwritten, so adjudication work cannot be lost.
"""
import csv
import random
from collections import Counter

from sklearn.metrics import cohen_kappa_score

from . import DATA, records
from .classify import llm_label, scores, split
from .dataset import CLASSES

GOLD = DATA / "gold" / "gold.csv"
PER_CLASS = 12
FIELDS = ["id", "description", "cwes", "nvd_class", "llm_class", "llm_rationale", "gold_class", "adjudication_note"]


def sample() -> list[dict]:
    """Stratified: PER_CLASS per class, from the TEST side of the grouped split (the baseline never trains on
    them), one record per near-duplicate cluster (no templated twins)."""
    _, test = split([r for r in records() if r["vuln_class"]])
    pool = [r for r in test if r["cluster"] == r["id"]]
    rng = random.Random(0)
    return [r for c in CLASSES for r in rng.sample([r for r in pool if r["vuln_class"] == c], PER_CLASS)]


def create() -> None:
    rows = []
    for r in sample():
        lab = llm_label(r["description"])
        agree = lab.vuln_class == r["vuln_class"]
        rows.append({"id": r["id"], "description": r["description"], "cwes": " ".join(r["cwes"]),
                     "nvd_class": r["vuln_class"], "llm_class": lab.vuln_class, "llm_rationale": lab.rationale,
                     "gold_class": r["vuln_class"] if agree else "", "adjudication_note": ""})
    GOLD.parent.mkdir(parents=True, exist_ok=True)
    with open(GOLD, "w", newline="") as f:
        w = csv.DictWriter(f, FIELDS)
        w.writeheader()
        w.writerows(rows)


def gold() -> list[dict]:
    with open(GOLD, newline="") as f:
        return list(csv.DictReader(f))


def report() -> dict:
    rows = gold()
    nvd, llm = [r["nvd_class"] for r in rows], [r["llm_class"] for r in rows]
    done = [r for r in rows if r["gold_class"]]
    out = {"n": len(rows), "raw_agreement": scores(nvd, llm)["accuracy"], "cohen_kappa": round(cohen_kappa_score(nvd, llm), 3),
           "adjudicated": len(done)}
    if done:
        g = [r["gold_class"] for r in done]
        out |= {"nvd_vs_gold": scores([r["nvd_class"] for r in done], g)["accuracy"],
                "llm_vs_gold": scores([r["llm_class"] for r in done], g)["accuracy"],
                "nvd_errors": Counter(f"{r['nvd_class']}->{r['gold_class']}" for r in done
                                      if r["nvd_class"] != r["gold_class"]).most_common()}
    return out


if __name__ == "__main__":
    if not GOLD.exists():
        create()
    print(report())
