"""CVEScope UI.  streamlit run app.py"""
import json

import streamlit as st

from cvescope import agent, team
from cvescope.classify import llm_label
from cvescope.dataset import CLASSES
from cvescope.llm import USAGE
from cvescope.summarize import summarize

st.set_page_config(page_title="CVEScope", page_icon="🛡️", layout="wide")
st.title("🛡️ CVEScope")
st.caption("Asistent pentru triajul vulnerabilităților · NVD + CISA KEV + EPSS · CVE-2025/2026")
with st.spinner("Se încarcă indexul (BM25 + embeddings + graf)..."):
    ix = agent.index()
st.sidebar.metric("CVE-uri indexate", f"{len(ix.recs):,}")
st.sidebar.metric("Cost LLM în sesiune (USD)", f"{USAGE['usd']:.4f}")
st.sidebar.caption(f"apeluri: {USAGE['calls']} · din cache: {USAGE['cache_hits']}")

chat_tab, search_tab, cve_tab, clf_tab = st.tabs(["💬 Asistent", "🔎 Căutare", "📄 CVE", "🏷️ Clasificare"])

with chat_tab:
    multi = st.toggle("Multi-agent: orchestrator → cercetători în paralel → judge (mai lent, verificat)")
    st.session_state.setdefault("chat", [])
    for m in st.session_state.chat:
        st.chat_message(m["role"]).markdown(m["content"])
    if q := st.chat_input("Ex: Ce vulnerabilități Fortinet din 2026 sunt exploatate activ?"):
        st.chat_message("user").markdown(q)
        with st.spinner("Agentul caută..."):
            out = team.orchestrate(q) if multi else agent.run(q, history=st.session_state.chat[-6:])
        st.chat_message("assistant").markdown(out["answer"])
        if out["ungrounded"]:
            st.warning(f"ID-uri care NU apar în rezultatele uneltelor (posibil inventate): {out['ungrounded']}")
        with st.expander("Traseul cererii (trace)"):
            st.json(out["trace"])
        st.session_state.chat += [{"role": "user", "content": q}, {"role": "assistant", "content": out["answer"]}]

with search_tab:
    q = st.text_input("Interogare", "remote code execution in VPN gateway")
    c = st.columns(5)
    mode = c[0].selectbox("Metodă", ["hybrid", "bm25", "dense"])
    severity = c[1].selectbox("Severitate", ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    vuln_class = c[2].selectbox("Clasă", ["", *CLASSES])
    vendor = c[3].text_input("Vendor / produs")
    kev_only = c[4].checkbox("Doar CISA KEV")
    if q:
        res = ix.search(q, k=20, mode=mode, severity=severity, vuln_class=vuln_class, vendor=vendor, kev_only=kev_only)
        st.dataframe([agent.brief(r) | {"score": r["score"]} for r in res], width="stretch")

with cve_tab:
    cid = st.text_input("CVE id (orice an; cele vechi se aduc live din NVD)", "CVE-2026-21589")
    r = agent.get_cve(cid) if cid else None
    if r and "error" in r:
        st.error(r["error"])
    elif r:
        cvss = r["cvss"] or {}
        c = st.columns(4)
        c[0].metric("CVSS", f"{cvss.get('score', '-')} {cvss.get('severity') or ''}")
        c[1].metric("EPSS", f"{r['epss']:.3f}" if r["epss"] is not None else "-")
        c[2].metric("CISA KEV", "DA" if r["kev"] else "nu")
        c[3].metric("Clasă", r["vuln_class"] or "-")
        st.write(r["description"])
        st.caption(f"{r.get('source', '')} · {r['published']} · {', '.join(r['cwes'])} · {', '.join(r['products'][:8])}")
        if st.button("Rezumat AI"):
            st.json(summarize(r).model_dump())
        if cid.upper() in ix.pos:
            st.subheader("CVE-uri înrudite (graf: produse / CWE comune)")
            st.dataframe([{"id": x["id"], "shared": x["shared"], "description": x["description"][:150]}
                          for x in ix.related(cid.upper())], width="stretch")
        with st.expander("Înregistrarea completă"):
            st.code(json.dumps(r, indent=1, ensure_ascii=False), language="json")

with clf_tab:
    st.write("Clasificarea tipului de vulnerabilitate pentru CVE-uri încă neanalizate de NVD (fără CWE).")
    text = st.text_area("Descriere", "A crafted request to /api/upload lets an unauthenticated attacker write "
                                     "files outside the web root via ../ sequences.")
    if st.button("Clasifică"):
        lab = llm_label(text)
        st.success(lab.vuln_class)
        st.caption(lab.rationale)
