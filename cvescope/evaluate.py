"""Step 8 - evaluation of every component -> data/results.json + docs/results.md (generated tables).

    python -m cvescope.evaluate                      # retrieval, classification, summaries, agents
    python -m cvescope.evaluate retrieval            # one section; the others keep their previous results
Costs and LLM seconds are the uncached numbers (stored with each cached call), so reruns report the same values.
"""
import json
import random
import sys
from concurrent.futures import ThreadPoolExecutor

import numpy as np

from . import DATA, ROOT, agent, records, team
from .annotate import gold
from .classify import baseline, llm_label, scores, split
from .llm import JUDGE_MODEL, MODEL, USAGE
from .summarize import evidence, summarize
from .synth import QUESTIONS

RESULTS = DATA / "results.json"
AGENT_QUESTIONS = DATA / "eval_questions.jsonl"
GOLD_MODELS = ["gpt-4.1-nano", "gpt-4.1-mini", "gpt-5-mini"]
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def spend(fn):
    """-> (fn(), usd, llm_seconds) for the LLM calls made inside fn."""
    before = USAGE.copy()
    out = fn()
    return out, USAGE["usd"] - before["usd"], USAGE["seconds"] - before["seconds"]


def avg(rows: list[dict], key: str):
    """Mean of rows[key], skipping rows that don't have it; None if no row has it."""
    vals = [r[key] for r in rows if r.get(key) is not None]
    return round(float(np.mean(vals)), 3) if vals else None


def retrieval() -> dict:
    ix, qs = agent.index(), [json.loads(line) for line in QUESTIONS.read_text().splitlines()]
    out = {}
    for mode in ("bm25", "dense", "hybrid"):
        ranks = []
        for q in qs:
            ids = [r["id"] for r in ix.search(q["question"], k=10, mode=mode)]
            ranks.append(ids.index(q["id"]) + 1 if q["id"] in ids else 0)  # 0 = not in top 10
        r = np.array(ranks)
        out[mode] = {"n": len(r), "recall@1": (r == 1).mean(), "recall@5": ((r > 0) & (r <= 5)).mean(),
                     "recall@10": (r > 0).mean(), "mrr@10": np.where(r > 0, 1 / np.maximum(r, 1), 0).mean()}
    return {m: {k: round(float(v), 3) for k, v in d.items()} for m, d in out.items()}


def classification() -> dict:
    out, labeled = {}, [r for r in records() if r["vuln_class"]]
    for name, grouped in (("random", False), ("grouped", True)):  # grouped last: its model is reused on gold
        tr, te = split(labeled, grouped)
        model = baseline(tr, lambda r: r["vuln_class"])
        out[f"vuln_class, {name} split"] = {"n_test": len(te), **scores(
            [r["vuln_class"] for r in te], model.predict([r["description"] for r in te]))}
    sev = [r for r in records() if (r["cvss"] or {}).get("severity") in SEVERITIES]
    tr, te = split(sev)
    sev_model = baseline(tr, lambda r: r["cvss"]["severity"])
    out["severity, grouped split"] = {"n_test": len(te), **scores(
        [r["cvss"]["severity"] for r in te], sev_model.predict([r["description"] for r in te]))}

    rows = [r for r in gold() if r["gold_class"]]
    g, desc = [r["gold_class"] for r in rows], [r["description"] for r in rows]
    out["gold: NVD/CNA label"] = {"n_test": len(rows), **scores(g, [r["nvd_class"] for r in rows])}
    out["gold: TF-IDF + LinearSVC"] = {"n_test": len(rows), **scores(g, model.predict(desc))}
    for m in GOLD_MODELS:
        with ThreadPoolExecutor(8) as ex:
            pred, usd, secs = spend(lambda: list(ex.map(lambda d: llm_label(d, m).vuln_class, desc)))
        out[f"gold: LLM {m}"] = {"n_test": len(rows), **scores(g, pred), "usd_per_1k": round(1000 * usd / len(rows), 3),
                                 "sec_per_call": round(secs / len(rows), 2)}
    return out


def row(q: dict, system: str, answer: str, verdict: dict, ungrounded: list, usd: float, secs: float, **extra) -> dict:
    expect = q.get("expect") or []
    return {"question": q["question"], "system": system, "answer": answer, "verdict": verdict, "ungrounded": ungrounded,
            **{k: verdict[k] for k in team.RUBRIC}, "passed": team.passed(verdict, ungrounded),
            "ungrounded_ids": len(ungrounded),
            "expected_id_recall": sum(i in answer for i in expect) / len(expect) if expect else None,
            "usd": usd, "llm_seconds": secs, **extra}


def agents() -> dict:
    """Every question goes through both systems; both are scored with the same judge and rubric."""
    rows = []
    for q in map(json.loads, AGENT_QUESTIONS.read_text().splitlines()):
        single, usd, secs = spend(lambda: agent.run(q["question"]))
        verdict = team.judge(q["question"], single["answer"], team.tool_outputs(single)).model_dump()
        rows.append(row(q, "single agent", single["answer"], verdict, single["ungrounded"], usd, secs))

        multi, usd, secs = spend(lambda: team.orchestrate(q["question"]))
        first = next(t for t in multi["trace"] if t["role"] == "judge")
        rows.append(row(q, "orchestrator + judge", multi["answer"], multi["verdict"], multi["ungrounded"], usd, secs,
                        rounds=multi["rounds"], first_draft_min_score=min(first[k] for k in team.RUBRIC)))
    (DATA / "agent_eval.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
    keys = [*team.RUBRIC, "passed", "ungrounded_ids", "expected_id_recall", "usd", "llm_seconds", "rounds",
            "first_draft_min_score"]
    out = {}
    for system in dict.fromkeys(r["system"] for r in rows):
        mine = [r for r in rows if r["system"] == system]
        out[system] = {"n": len(mine), **{k: avg(mine, k) for k in keys}}
    return out


def summaries(n: int = 15) -> dict:
    rows = []
    for r in random.Random(2).sample([r for r in records() if r["kev"]], n):
        s, usd, secs = spend(lambda: summarize(r))
        verdict = team.judge(f"Summarize {r['id']} for a sysadmin.", s.model_dump_json(), evidence(r)).model_dump()
        rows.append(verdict | {"passed": team.passed(verdict), "usd": usd, "secs": secs})
    return {"summaries of CISA KEV CVEs": {"n": n, **{k: avg(rows, k) for k in (*team.RUBRIC, "passed")},
                                           "usd_per_summary": round(avg(rows, "usd"), 5),
                                           "sec_per_summary": avg(rows, "secs")}}


def table(section: dict) -> str:
    cols = list(dict.fromkeys(k for row in section.values() for k in row))
    lines = ["| | " + " | ".join(cols) + " |", "|---" * (len(cols) + 1) + "|"]
    return "\n".join(lines + [f"| {name} | " + " | ".join(str(row.get(c, "")) for c in cols) + " |"
                              for name, row in section.items()])


if __name__ == "__main__":
    sections = {"retrieval": retrieval, "classification": classification, "summaries": summaries, "agents": agents}
    results = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    for name in sys.argv[1:] or sections:
        results[name] = sections[name]()
        print(name, json.dumps(results[name], indent=1))
    RESULTS.write_text(json.dumps(results, indent=1))
    md = [f"# Rezultate (generat de `python -m cvescope.evaluate`)\n\nModel: `{MODEL}`, judge: `{JUDGE_MODEL}`. "
          "Metodologia: [evaluation.md](evaluation.md).\n"]
    md += [f"## {name}\n\n{table(sec)}\n" for name, sec in results.items()]
    (ROOT / "docs" / "results.md").write_text("\n".join(md))
