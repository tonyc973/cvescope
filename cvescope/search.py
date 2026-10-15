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
    """Okapi BM25. The CSC term-document matrix is an inverted index: column t = posting list of term t."""

    def __init__(self, texts: list[str], k1: float = 1.5, b: float = 0.75):
        self.cv = CountVectorizer(stop_words="english", dtype=np.float32)
        self.tf = self.cv.fit_transform(texts).tocsc()
        df = np.diff(self.tf.indptr)  # documents containing each term
        dl = np.asarray(self.tf.sum(axis=1)).ravel()
        self.idf = np.log(1 + (len(texts) - df + 0.5) / (df + 0.5)).astype(np.float32)
        self.k1, self.norm = k1, (k1 * (1 - b + b * dl / dl.mean())).astype(np.float32)
        self.analyze, self.vocab = self.cv.build_analyzer(), self.cv.vocabulary_

    def scores(self, query: str) -> np.ndarray:
        s = np.zeros(self.tf.shape[0], dtype=np.float32)
        for t in {self.vocab[w] for w in self.analyze(query) if w in self.vocab}:
            lo, hi = self.tf.indptr[t], self.tf.indptr[t + 1]  # only documents that contain t are touched
            rows, f = self.tf.indices[lo:hi], self.tf.data[lo:hi]
            s[rows] += self.idf[t] * f * (self.k1 + 1) / (f + self.norm[rows])
        return s


def top(scores: np.ndarray, mask: np.ndarray, k: int) -> list[int]:
    s = np.where(mask, scores, -np.inf)
    idx = np.argpartition(-s, min(k, len(s) - 1))[:k]  # O(n) selection instead of a full sort
    return [int(i) for i in idx[np.argsort(-s[idx])] if s[i] > 0]


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
        self.pos = {r["id"]: i for i, r in enumerate(self.recs)}
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
        """2-hop graph walk CVE -> {products, CWEs} -> CVEs. A shared product weighs 2, a shared CWE 1."""
        r = self.recs[self.pos[cve_id]]
        score = Counter()
        for node in r["products"] + r["cwes"]:
            for j in self.graph[node]:
                score[j] += 1 if node.startswith("CWE-") else 2
        score.pop(self.pos[cve_id], None)
        best = sorted(score, key=lambda j: (-score[j], -(self.recs[j]["epss"] or 0)))[:k]
        nodes = set(r["products"] + r["cwes"])
        return [self.recs[j] | {"shared": sorted(nodes & set(self.recs[j]["products"] + self.recs[j]["cwes"]))}
                for j in best]

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
