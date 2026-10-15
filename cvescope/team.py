"""Step 6 - multi-agent: Orchestrator (plans) -> Researchers (agent.run, in parallel) -> Writer -> Judge,
with a self-refine loop (Madaan et al., 2023) that stops when the Judge passes the answer or after max_rounds.
Every step is appended to `trace`, so a request can be followed end to end.

    python -m cvescope.team "Compara vulnerabilitatile Fortinet si Ivanti din 2026 exploatate activ"
"""
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor

from pydantic import BaseModel, Field

from . import agent
from .llm import JUDGE_MODEL, MODEL, USAGE, chat, structured


class Plan(BaseModel):
    subtasks: list[str] = Field(description="1-3 self-contained sub-questions; just 1 if the question is simple")


class Verdict(BaseModel):
    feedback: str = Field(description="concrete problems to fix; empty if none")
    grounded: int = Field(description="1-5: every id, score, product and version is supported by the evidence")
    complete: int = Field(description="1-5: answers every part of the question")
    useful: int = Field(description="1-5: clear, concise, prioritized when the user must act")


PASS = 4  # stop criterion: every rubric score >= PASS and no ungrounded CVE id


def judge(question: str, answer: str, evidence: str, model: str = JUDGE_MODEL) -> Verdict:
    return structured([
        {"role": "system", "content": "You are a strict reviewer of answers about software vulnerabilities. "
                                      "Judge ONLY against the evidence (tool outputs); do not use outside knowledge."},
        {"role": "user", "content": f"Question:\n{question}\n\nAnswer:\n{answer}\n\nEvidence:\n{evidence[:30000]}"},
    ], Verdict, model=model)


def passed(v: Verdict, ungrounded: list) -> bool:
    return min(v.grounded, v.complete, v.useful) >= PASS and not ungrounded


def tool_outputs(result: dict) -> str:
    return "\n".join(m["content"] for m in result["messages"] if m["role"] == "tool")


def orchestrate(question: str, max_rounds: int = 3, model: str = MODEL) -> dict:
    trace, t0 = [], time.time()
    log = lambda role, **kw: trace.append({"role": role, "t": round(time.time() - t0, 1), **kw})

    plan = structured([{"role": "user", "content": "Split this vulnerability-triage question into 1-3 "
                        f"self-contained sub-questions that can be researched independently:\n{question}"}],
                      Plan, model=model)
    subtasks = plan.subtasks[:3] or [question]
    log("orchestrator", subtasks=subtasks)

    agent.index()  # build the shared index once, before the threads use it
    with ThreadPoolExecutor(len(subtasks)) as ex:  # independent sub-questions run in parallel
        runs = list(ex.map(lambda q: agent.run(q, model=model), subtasks))
    for q, r in zip(subtasks, runs):
        log("researcher", subtask=q, tools=[t["tool"] for t in r["trace"]], answer=r["answer"])
    evidence = "\n".join(tool_outputs(r) for r in runs)
    ids = set().union(*(r["evidence"] for r in runs))

    if len(runs) == 1:
        answer = runs[0]["answer"]
    else:
        notes = "\n\n".join(f"### {q}\n{r['answer']}" for q, r in zip(subtasks, runs))
        answer = chat([{"role": "system", "content": agent.SYSTEM.format(today=time.strftime("%Y-%m-%d"))},
                       {"role": "user", "content": f"Question: {question}\n\nResearch notes:\n{notes}\n\n"
                                                   "Write the final answer using only these notes."}],
                      model=model)["content"]
        log("writer", answer=answer)

    for round_ in range(1, max_rounds + 1):
        ungrounded = sorted(set(agent.CVE_RE.findall(answer)) - ids - set(agent.CVE_RE.findall(question)))
        verdict = judge(question, answer, evidence)
        log("judge", round=round_, ungrounded=ungrounded, **verdict.model_dump())
        if passed(verdict, ungrounded) or round_ == max_rounds:
            break
        fix = (f"{question}\n\nA reviewer rejected this draft answer:\n{answer}\n\nFeedback: {verdict.feedback}\n"
               f"Ids not supported by evidence: {ungrounded or 'none'}.\nResearch again where needed and write a "
               "corrected final answer.")
        r = agent.run(fix, model=model)
        answer, evidence, ids = r["answer"], evidence + "\n" + tool_outputs(r), ids | set(r["evidence"])
        log("researcher", subtask="revision", tools=[t["tool"] for t in r["trace"]], answer=answer)

    return {"answer": answer, "trace": trace, "rounds": round_, "verdict": verdict.model_dump(),
            "passed": passed(verdict, ungrounded), "ungrounded": ungrounded}


if __name__ == "__main__":
    out = orchestrate(" ".join(sys.argv[1:]))
    for step in out["trace"]:
        print(json.dumps({k: (v[:200] if isinstance(v, str) else v) for k, v in step.items()}, ensure_ascii=False))
    print("\n" + out["answer"] + f"\n\npassed={out['passed']} rounds={out['rounds']} usage={dict(USAGE)}")
