"""Offline tests (no API key, no network): python -m pytest -q"""
import os
import tempfile

os.environ["CVESCOPE_DATA"] = tempfile.mkdtemp()  # isolated LLM cache, before importing the package

import numpy as np

from cvescope import agent, llm
from cvescope.dataset import near_dup_clusters, parse_nvd, vuln_class
from cvescope.search import BM25, Index, rrf
from cvescope.synth import copies_description


def rec(i, desc, products=(), cwes=(), sev="HIGH", kev=None, epss=0.0, published="2026-01-01"):
    return {"id": f"CVE-2026-{1000 + i}", "description": desc, "products": list(products), "cwes": list(cwes),
            "vuln_class": vuln_class(list(cwes)), "cvss": {"severity": sev, "score": 7.5}, "kev": kev,
            "epss": epss, "published": published, "cluster": f"CVE-2026-{1000 + i}"}


RECS = [
    rec(0, "SQL injection in the login form of Acme Shop allows attackers to dump the database",
        ["acme:shop"], ["CWE-89"], kev={"date_added": "2026-02-01"}, epss=0.9),
    rec(1, "Stored cross-site scripting in Acme Shop product reviews", ["acme:shop"], ["CWE-79"], sev="MEDIUM"),
    rec(2, "Heap buffer overflow in libfoo image parser leads to code execution", ["foo:libfoo"], ["CWE-122"],
        epss=0.2, published="2025-06-01"),
]


def test_taxonomy_priority():
    assert vuln_class(["CWE-74", "CWE-89"]) == "sqli"  # specific child beats generic "injection"
    assert vuln_class(["CWE-9999"]) == "other"
    assert vuln_class([]) is None


def test_parse_nvd():
    r = parse_nvd({"id": "CVE-2026-1", "published": "2026-03-04T10:00:00", "vulnStatus": "Analyzed",
                   "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "bug"}],
                   "weaknesses": [{"description": [{"value": "CWE-79"}, {"value": "NVD-CWE-noinfo"}]}],
                   "metrics": {"cvssMetricV31": [
                       {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 5.0, "vectorString": "v2", "baseSeverity": "MEDIUM"}},
                       {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8, "vectorString": "v1", "baseSeverity": "CRITICAL"}}]},
                   "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:2.3:a:acme:shop:1.0:*:*:*:*:*:*:*"}]}]}],
                   "affected": [{"affectedData": [{"vendor": "n/a", "product": "n/a"}, {"vendor": "Acme Inc", "product": "Shop Pro"}]}]})
    assert r["description"] == "bug" and r["cwes"] == ["CWE-79"] and r["vuln_class"] == "xss"
    assert r["cvss"]["score"] == 9.8  # NVD's Primary score wins over the CNA's
    assert r["products"] == ["acme:shop", "acme_inc:shop_pro"]  # n/a placeholder dropped


def test_near_dup_clusters():
    a = "The Foo plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the title parameter in all versions up to 1.2"
    b = a.replace("1.2", "1.3")
    reps = near_dup_clusters([a, "Heap overflow in libpng when decoding malformed chunks", b])
    assert reps == [0, 1, 0]


def test_bm25_and_rrf():
    s = BM25([r["description"] for r in RECS]).scores("database sql injection")
    assert s.argmax() == 0 and s[2] == 0
    fused = rrf([[0, 1], [1, 2]])
    assert fused[0][0] == 1 and abs(fused[0][1] - (1 / 62 + 1 / 61)) < 1e-9


def make_index(monkeypatch):
    emb = np.eye(3, dtype=np.float32)
    monkeypatch.setattr("cvescope.search.embed_query", lambda q: np.array([0, 0, 1], dtype=np.float32))
    return Index(RECS, emb)


def test_index_search_filters_graph_stats(monkeypatch):
    ix = make_index(monkeypatch)
    assert ix.search("sql injection", mode="bm25")[0]["id"] == "CVE-2026-1000"
    assert ix.search("anything", mode="dense")[0]["id"] == "CVE-2026-1002"
    assert [r["id"] for r in ix.search("acme", kev_only=True)] == ["CVE-2026-1000"]
    assert {r["id"] for r in ix.search("injection", vendor="Acme Shop")} <= {"CVE-2026-1000", "CVE-2026-1001"}
    assert ix.mask(vendor="Acme Shop").sum() == 2
    assert [r["id"] for r in ix.search("acme shop", severity="medium", mode="bm25")] == ["CVE-2026-1001"]
    assert ix.search("overflow", since="2026-01-01", mode="bm25") == []
    rel = ix.related("CVE-2026-1000")
    assert rel[0]["id"] == "CVE-2026-1001" and rel[0]["shared"] == ["acme:shop"]
    st = ix.stats(vendor="Acme")
    assert st["count"] == 2 and st["in_cisa_kev"] == 1 and st["top_products"][0] == ("acme:shop", 2)
    assert st["ids"] == ["CVE-2026-1000", "CVE-2026-1001"]  # small result sets are listed in full


def test_agent_loop_and_grounding(monkeypatch):
    ix = make_index(monkeypatch)
    monkeypatch.setattr(agent, "index", lambda: ix)
    replies = iter([
        {"role": "assistant", "tool_calls": [{"id": "1", "type": "function", "function": {
            "name": "search_cves", "arguments": '{"query": "sql injection acme", "kev_only": true}'}}]},
        {"role": "assistant", "content": "Patch CVE-2026-1000 first; also CVE-2026-9999."},
    ])
    monkeypatch.setattr(agent, "chat", lambda *a, **k: next(replies))
    out = agent.run("what should I patch in acme?")
    assert out["trace"][0]["tool"] == "search_cves"
    assert out["ungrounded"] == ["CVE-2026-9999"]  # invented id is caught
    res = agent.search_cves("shop", k=1, vendor="acme")
    assert res["cves_matching_filters"] == 2 and len(res["results"]) == 1 and "cve_stats" in res["note"]


def test_prioritize_and_input_validation(monkeypatch):
    ix = make_index(monkeypatch)
    monkeypatch.setattr(agent, "index", lambda: ix)
    order = [r["id"] for r in agent.prioritize(["CVE-2026-1002", "CVE-2026-1001", "CVE-2026-1000"])]
    assert order == ["CVE-2026-1000", "CVE-2026-1002", "CVE-2026-1001"]  # KEV, then EPSS
    assert "error" in agent.get_cve("CVE-2026-1; rm -rf /")


def test_memo_pays_once():
    calls = []
    usage = type("U", (), {"prompt_tokens": 10, "completion_tokens": 5})()
    fn = lambda: (calls.append(1) or "answer", usage)
    assert llm.memo({"model": "gpt-4.1-mini", "x": 1}, fn) == llm.memo({"model": "gpt-4.1-mini", "x": 1}, fn) == "answer"
    assert len(calls) == 1


def test_synthetic_question_validation():
    d = "The Foo plugin for WordPress is vulnerable to SQL injection via the id parameter"
    assert copies_description("is the foo plugin for wordpress is vulnerable to sql injection?", d)
    assert not copies_description("Can attackers inject database queries through the Foo WordPress plugin?", d)
