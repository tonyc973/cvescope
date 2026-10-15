"""Step 7 - synthetic evaluation data: realistic search questions whose answer is one known CVE.

    python -m cvescope.synth --n 200     # -> data/synth/questions.jsonl
Validation (rejects a question): it leaks the CVE id, or it copies >= 6 consecutive words of the description
(that would make lexical search trivially win).
"""
import argparse
import json
import random
import re
from collections import Counter

from pydantic import BaseModel

from . import DATA, records
from .agent import CVE_RE
from .llm import structured

QUESTIONS = DATA / "synth" / "questions.jsonl"


class Question(BaseModel):
    question: str


def copies_description(question: str, description: str, n: int = 6) -> bool:
    w = re.findall(r"\w+", question.lower())
    d = " ".join(re.findall(r"\w+", description.lower()))
    return any(" ".join(w[i:i + n]) in d for i in range(len(w) - n + 1))


def generate(n: int, seed: int = 1) -> None:
    sizes = Counter(r["cluster"] for r in records())
    pool = [r for r in records() if sizes[r["cluster"]] == 1]  # unique descriptions -> one unambiguous target
    rows, rejected = [], 0
    for r in random.Random(seed).sample(pool, n):
        q = structured([
            {"role": "system", "content": "You write realistic queries that a sysadmin or security engineer types "
                                          "into a vulnerability search tool."},
            {"role": "user", "content": f"Vulnerability:\n{r['description']}\nProducts: {', '.join(r['products'][:3])}\n\n"
                                        "Write ONE question (one sentence) whose answer is this vulnerability. Name the "
                                        "product, but describe the weakness in your own words. Do not copy phrases from "
                                        "the text, do not include the CVE id or exact version numbers."},
        ], Question).question
        if CVE_RE.search(q) or copies_description(q, r["description"]):
            rejected += 1
            continue
        rows.append({"id": r["id"], "question": q})
    QUESTIONS.parent.mkdir(parents=True, exist_ok=True)
    QUESTIONS.write_text("".join(json.dumps(x, ensure_ascii=False) + "\n" for x in rows))
    print(f"kept {len(rows)}, rejected {rejected} -> {QUESTIONS}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    generate(ap.parse_args().n)
