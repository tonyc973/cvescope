"""Step 2 - search: BM25 (own, on a sparse matrix) + dense embeddings, fused with Reciprocal Rank Fusion,
plus a CVE-product-CWE graph for "related CVEs" and aggregate (global) questions.

    python -m cvescope.search --build                 # embed all records -> data/embeddings.npy (~$0.30, ~15 min)
    python -m cvescope.search "sql injection in a wordpress booking plugin"
"""
import argparse
from collections import Counter, defaultdict

import numpy as np
from sklearn.feature_extraction.text import CountVectorizer

from . import DATA, records
from .dataset import _norm
from .llm import embed, embed_query

EMB = DATA / "embeddings.npy"


def doc_text(r: dict) -> str:
    return f"{r['id']} {r['description']} {' '.join(r['products'][:10])}".replace("_", " ").replace(":", " ")


class BM25:
    """Okapi BM25:  score(d) = sum over query terms t of  idf(t) * tf * (k1 + 1) / (tf + k1 * (1 - b + b * |d| / avg|d|))
    where tf = how many times t occurs in document d."""

    def __init__(self, texts: list[str], k1: float = 1.5, b: float = 0.75):
        self.vectorizer = CountVectorizer(stop_words="english", dtype=np.float32)
        # counts[d, t] = occurrences of term t in document d, stored column by column (CSC):
        # column t lists exactly the documents that contain t, i.e. CSC is an inverted index
        self.counts = self.vectorizer.fit_transform(texts).tocsc()
        docs_with_term = np.diff(self.counts.indptr)
        doc_len = np.asarray(self.counts.sum(axis=1)).ravel()
        self.idf = np.log(1 + (len(texts) - docs_with_term + 0.5) / (docs_with_term + 0.5)).astype(np.float32)
        # the part of the denominator that depends only on the document, computed once
        self.len_norm = (k1 * (1 - b + b * doc_len / doc_len.mean())).astype(np.float32)
        self.k1 = k1

    def scores(self, query: str) -> np.ndarray:
        vocab = self.vectorizer.vocabulary_
        terms = {vocab[w] for w in self.vectorizer.build_analyzer()(query) if w in vocab}
        scores = np.zeros(self.counts.shape[0], dtype=np.float32)
        for t in terms:
            start, end = self.counts.indptr[t], self.counts.indptr[t + 1]  # term t's slice of the inverted index
            docs, tf = self.counts.indices[start:end], self.counts.data[start:end]  # which documents, how many times
            scores[docs] += self.idf[t] * tf * (self.k1 + 1) / (tf + self.len_norm[docs])
        return scores


def top(scores: np.ndarray, mask: np.ndarray, k: int) -> list[int]:
    """Positions of the k best documents allowed by `mask`, best first; only positive scores count."""
    scores = np.where(mask, scores, -np.inf)  # filtered-out documents can never win
    best = np.argpartition(-scores, min(k, len(scores) - 1))[:k]  # the k largest, unordered: O(n), no full sort
    best = best[np.argsort(-scores[best])]  # sort just those k
    return [int(i) for i in best if scores[i] > 0]


def rrf(runs: list[list[int]], k: int = 60) -> list[tuple[int, float]]:
    """Reciprocal Rank Fusion (Cormack et al., 2009): score(d) = sum over rankings of 1 / (k + rank(d))."""
    fused = defaultdict(float)
    for run in runs:
        for rank, i in enumerate(run, 1):
            fused[i] += 1 / (k + rank)
    return sorted(fused.items(), key=lambda x: -x[1])


class Index:
    def __init__(self, recs: list[dict] | None = None, emb: np.ndarray | None = None):
        self.recs = recs if recs is not None else records()
        self.emb = emb if emb is not None else np.load(EMB)
        assert len(self.emb) == len(self.recs), "embeddings are stale: run `python -m cvescope.search --build`"
        self.bm25 = BM25([doc_text(r) for r in self.recs])
        self.pos = {r["id"]: i for i, r in enumerate(self.recs)}  # CVE id -> row number
        # one array per filterable field, so a filter is a single vectorized comparison
        self.sev = np.array([(r["cvss"] or {}).get("severity") or "" for r in self.recs])
        self.cls = np.array([r["vuln_class"] or "" for r in self.recs])
        self.kev = np.array([bool(r["kev"]) for r in self.recs])
        self.pub = np.array([r["published"] for r in self.recs])
        self.prod = [" ".join(r["products"]).replace(":", "_") for r in self.recs]  # "ivanti_connect_secure" matches
        self.graph = defaultdict(list)  # bipartite graph: product / CWE node -> CVE positions
        for i, r in enumerate(self.recs):
            for node in r["products"] + r["cwes"]:
                self.graph[node].append(i)

    def mask(self, severity=None, vuln_class=None, kev_only=False, vendor=None, since=None) -> np.ndarray:
        m = np.ones(len(self.recs), dtype=bool)
        if severity:
            m &= self.sev == severity.upper()
        if vuln_class:
            m &= self.cls == vuln_class
        if kev_only:
            m &= self.kev
        if since:
            m &= self.pub >= since  # ISO dates compare correctly as strings
        if vendor:
            v = _norm(vendor)
            m &= np.array([v in p for p in self.prod])
        return m

    def search(self, query: str, k: int = 10, mode: str = "hybrid", **filters) -> list[dict]:
        m = self.mask(**filters)
        runs = []
        if mode in ("bm25", "hybrid"):
            runs.append(top(self.bm25.scores(query), m, 50))
        if mode in ("dense", "hybrid"):
            runs.append(top(self.emb @ embed_query(query), m, 50))
        return [self.recs[i] | {"score": round(s, 4)} for i, s in rrf(runs)[:k]]

    def related(self, cve_id: str, k: int = 5) -> list[dict]:
        """2-hop graph walk CVE -> {products, CWEs} -> other CVEs. A shared product weighs 2, a shared CWE 1."""
        me = self.recs[self.pos[cve_id]]
        my_nodes = me["products"] + me["cwes"]
        score = Counter()
        for node in my_nodes:
            weight = 1 if node.startswith("CWE-") else 2  # same product says more than same weakness type
            for j in self.graph[node]:
                score[j] += weight
        score.pop(self.pos[cve_id], None)  # not related to itself
        best = sorted(score, key=lambda j: (-score[j], -(self.recs[j]["epss"] or 0)))[:k]  # ties: higher EPSS first
        result = []
        for j in best:
            other = self.recs[j]
            shared = set(my_nodes) & set(other["products"] + other["cwes"])
            result.append(other | {"shared": sorted(shared)})
        return result

    def stats(self, top_n: int = 10, **filters) -> dict:
        """Aggregates over ALL matching CVEs - answers global questions that top-k retrieval cannot."""
        rs = [self.recs[i] for i in np.flatnonzero(self.mask(**filters))]
        return {
            "count": len(rs),
            "ids": [r["id"] for r in rs] if len(rs) <= 30 else "more than 30: narrow the filters to list them",
            "in_cisa_kev": sum(bool(r["kev"]) for r in rs),
            "by_class": Counter(r["vuln_class"] or "unlabeled (no CWE yet)" for r in rs).most_common(),
            "by_severity": Counter((r["cvss"] or {}).get("severity") or "unscored" for r in rs).most_common(),
            "by_month": sorted(Counter(r["published"][:7] for r in rs).items()),
            "top_products": Counter(p for r in rs for p in r["products"]).most_common(top_n),
            "highest_epss": [(r["id"], r["epss"]) for r in sorted(rs, key=lambda r: -(r["epss"] or 0))[:top_n]],
        }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("query", nargs="?")
    ap.add_argument("--build", action="store_true")
    ap.add_argument("--mode", default="hybrid", choices=["bm25", "dense", "hybrid"])
    args = ap.parse_args()
    if args.build:
        np.save(EMB, embed([doc_text(r) for r in records()]))
        print(f"\nsaved {EMB}")
    if args.query:
        for r in Index().search(args.query, mode=args.mode):
            print(r["id"], r["score"], (r["cvss"] or {}).get("severity"), r["description"][:110])
