"""Step 5 - tool-using agent (ReAct via function calling) over the dataset, the graph and the live NVD API.

    python -m cvescope.agent "Ce vulnerabilitati exploatate activ au aparut in 2026 pentru Fortinet?"
"""
import datetime
import json
import re
import sys
import urllib.request
from functools import lru_cache

from .dataset import CLASSES, load_kev, parse_nvd
from .llm import MODEL, USAGE, chat
from .search import Index

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


@lru_cache(maxsize=1)
def index() -> Index:
    return Index()


def brief(r: dict) -> dict:
    cvss = r["cvss"] or {}
    return {"id": r["id"], "published": r["published"], "severity": cvss.get("severity"), "cvss": cvss.get("score"),
            "class": r["vuln_class"], "cwes": r["cwes"], "in_cisa_kev": bool(r["kev"]), "epss": r["epss"],
            "products": r["products"][:5], "description": r["description"][:400]}


def search_cves(query: str, k: int = 8, **filters) -> dict:
    hits = [brief(r) for r in index().search(query, k=min(k, 15), **filters)]
    out = {"cves_matching_filters": int(index().mask(**filters).sum()), "results": hits}
    if filters and out["cves_matching_filters"] > len(hits):  # tell the model the list is truncated
        out["note"] = "only the top results are shown; call cve_stats with the same filters to count/list all"
    return out


def get_cve(cve_id: str) -> dict:
    cve_id = cve_id.strip().upper()
    if not CVE_RE.fullmatch(cve_id):  # model-produced text goes into a URL below
        return {"error": f"not a CVE id: {cve_id!r}"}
    if cve_id in index().pos:
        return index().recs[index().pos[cve_id]] | {"source": "local dataset"}
    return fetch_live(cve_id)


def fetch_live(cve_id: str) -> dict:
    """Web extraction: NVD API 2.0 + FIRST EPSS API, parsed with the same parser as the dataset."""
    get = lambda url: json.load(urllib.request.urlopen(
        urllib.request.Request(url, headers={"User-Agent": "cvescope (student project)"}), timeout=30))
    nvd = get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}")["vulnerabilities"]
    if not nvd:
        return {"error": f"{cve_id} not found in NVD"}
    epss = get(f"https://api.first.org/data/v1/epss?cve={cve_id}")["data"]
    return parse_nvd(nvd[0]["cve"]) | {"kev": load_kev().get(cve_id), "source": "live NVD API",
                                       "epss": float(epss[0]["epss"]) if epss else None}


def related_cves(cve_id: str, k: int = 5) -> list[dict]:
    if cve_id not in index().pos:
        return [{"error": f"{cve_id} is not in the local dataset (graph covers CVE-2025/2026 only)"}]
    return [brief(r) | {"shared": r["shared"]} for r in index().related(cve_id, k=min(k, 10))]


def cve_stats(**filters) -> dict:
    return index().stats(**filters)


def prioritize(cve_ids: list[str]) -> list[dict]:
    """Deterministic triage order: known exploited (CISA KEV) > exploit probability (EPSS) > CVSS score."""
    recs = [r for r in map(get_cve, cve_ids) if "error" not in r]
    recs.sort(key=lambda r: (not r["kev"], -(r["epss"] or 0), -((r["cvss"] or {}).get("score") or 0)))
    return [{"rank": i, "id": r["id"], "in_cisa_kev": bool(r["kev"]), "epss": r["epss"],
             "cvss": (r["cvss"] or {}).get("score")} for i, r in enumerate(recs, 1)]


FILTERS = {
    "severity": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
    "vuln_class": {"type": "string", "enum": CLASSES},
    "kev_only": {"type": "boolean", "description": "only CVEs known to be exploited (CISA KEV)"},
    "vendor": {"type": "string", "description": "vendor or product name, e.g. 'fortinet', 'wordpress'"},
    "since": {"type": "string", "description": "published on/after this date, YYYY-MM-DD"},
}


def _tool(fn, desc, props, required=()):
    return {"type": "function", "function": {"name": fn.__name__, "description": desc, "parameters": {
        "type": "object", "properties": props, "required": list(required)}}}


TOOLS = [
    _tool(search_cves, "Hybrid (BM25 + semantic) search over CVE-2025/2026 records. Use for topical questions.",
          {"query": {"type": "string"}, "k": {"type": "integer"}, **FILTERS}, ["query"]),
    _tool(get_cve, "Full record of one CVE (any year; non-2025/2026 CVEs are fetched live from NVD).",
          {"cve_id": {"type": "string"}}, ["cve_id"]),
    _tool(related_cves, "CVEs sharing products/CWEs with a given CVE (knowledge-graph walk).",
          {"cve_id": {"type": "string"}, "k": {"type": "integer"}}, ["cve_id"]),
    _tool(cve_stats, "Counts, top lists and (up to 30) all ids over ALL matching CVEs. Use for 'how many', "
                     "'list all', 'which products', trends - search_cves only returns the top k.",
          FILTERS),
    _tool(prioritize, "Order CVE ids by patch priority (KEV > EPSS > CVSS).",
          {"cve_ids": {"type": "array", "items": {"type": "string"}}}, ["cve_ids"]),
]
FUNCS = {f.__name__: f for f in (search_cves, get_cve, related_cves, cve_stats, prioritize)}

SYSTEM = """You are CVEScope, an assistant for vulnerability triage. Today is {today}.
Find facts with the tools; never invent CVE ids, scores, versions or products. Cite every CVE you mention by id.
The local dataset holds CVE-2025-* and CVE-2026-* from NVD, enriched with CISA KEV (known exploited) and EPSS
(probability of exploitation in the next 30 days); get_cve fetches older CVEs live from NVD.
If the tools return nothing relevant, say so plainly. Answer in the user's language, concisely.
When the user must act, prioritize: in CISA KEV first, then high EPSS, then CVSS."""


def ungrounded(answer: str, evidence: set, question: str) -> list[str]:
    """Grounding check: CVE ids in the answer that come neither from a tool result nor from the question."""
    return sorted(set(CVE_RE.findall(answer)) - evidence - set(CVE_RE.findall(question)))


def run(question: str, history: list | None = None, model: str = MODEL, max_steps: int = 8) -> dict:
    messages = [{"role": "system", "content": SYSTEM.format(today=datetime.date.today())},
                *(history or []), {"role": "user", "content": question}]
    trace, evidence = [], set()
    for _ in range(max_steps):
        msg = chat(messages, model=model, tools=TOOLS)
        messages.append(msg)
        if not msg.get("tool_calls"):
            break
        for tc in msg["tool_calls"]:
            name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"]["arguments"] or "{}")
                out = FUNCS[name](**args)
            except Exception as e:  # the error goes back to the model so it can correct its call
                args, out = tc["function"]["arguments"], {"error": f"{type(e).__name__}: {e}"}
            text = json.dumps(out, default=str, ensure_ascii=False)[:12000]
            evidence |= set(CVE_RE.findall(text))
            trace.append({"tool": name, "args": args, "result": text[:300]})
            messages.append({"role": "tool", "tool_call_id": tc["id"], "content": text})
    answer = msg.get("content") or "(no answer: step limit reached)"
    return {"answer": answer, "trace": trace, "evidence": sorted(evidence),
            "ungrounded": ungrounded(answer, evidence, question), "messages": messages}


if __name__ == "__main__":
    out = run(" ".join(sys.argv[1:]))
    for t in out["trace"]:
        print(f"  -> {t['tool']}({json.dumps(t['args'], ensure_ascii=False)})")
    print("\n" + out["answer"])
    print(f"\nungrounded ids: {out['ungrounded'] or 'none'} | usage: {dict(USAGE)}")
