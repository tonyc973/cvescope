"""Step 1 - dataset: download NVD + CISA KEV + EPSS + CWE, normalize, label, near-dedup.

    python -m cvescope.dataset --years 2025 2026      # download (cached in data/raw) + build data/cves.jsonl.gz
    python -m cvescope.dataset --stats                # print the dataset card numbers
"""
import argparse
import csv
import gzip
import io
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections import Counter

import numpy as np

from . import DATA, DATASET, records

RAW = DATA / "raw"
NVD_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{}.json.gz"
SOURCES = {
    "kev.json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss.csv.gz": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
    "cwec.xml.zip": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
}

# Annotation guideline (docs/annotation_guidelines.md): CWE -> coarse vulnerability class.
# A CVE may list several CWEs; the first class in this order wins, so specific classes (sqli)
# beat their generic parents (CWE-74 "injection"). CWEs not listed here -> "other".
TAXONOMY = {
    "sqli": [89, 564, 943],
    "xss": [79, 80, 83, 87],
    "csrf": [352],
    "ssrf": [918],
    "deserialization": [502],
    "path_file": [22, 23, 24, 35, 36, 59, 61, 73, 427, 428, 434],
    "code_injection": [74, 75, 77, 78, 88, 91, 94, 95, 96, 98, 917, 1336],
    "memory": [119, 120, 121, 122, 124, 125, 126, 127, 129, 131, 190, 191, 415, 416, 476, 680, 787, 788,
               805, 823, 824, 843, 908, 909],
    "access_control": [250, 266, 269, 276, 284, 285, 287, 288, 290, 294, 306, 307, 425, 521, 522, 639, 640,
                       732, 798, 862, 863, 1390, 1391],
    "info_leak": [200, 201, 203, 209, 212, 215, 312, 319, 359, 497, 532, 538, 552],
    "dos": [400, 401, 404, 674, 703, 754, 755, 770, 772, 789, 834, 835, 1333],
}
CLASSES = [*TAXONOMY, "other"]
_CWE2CLASS = {f"CWE-{n}": c for c, ns in TAXONOMY.items() for n in ns}


def vuln_class(cwes: list[str]) -> str | None:
    """None = no usable CWE (unlabeled, e.g. not yet analyzed by NVD)."""
    if not cwes:
        return None
    found = {_CWE2CLASS.get(c, "other") for c in cwes}
    return next(c for c in CLASSES if c in found)


def download(years: list[int]) -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    urls = {f"nvdcve-2.0-{y}.json.gz": NVD_FEED.format(y) for y in years} | SOURCES
    for name, url in urls.items():
        if not (RAW / name).exists():
            print("download", url)
            req = urllib.request.Request(url, headers={"User-Agent": "cvescope (student project)"})
            (RAW / name).write_bytes(urllib.request.urlopen(req, timeout=120).read())


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_") or "n_a"


def parse_nvd(c: dict) -> dict:
    """One NVD API 2.0 'cve' object -> our flat record. Same schema for the yearly feeds and the live API."""
    cwes = {d["value"] for w in c.get("weaknesses", []) for d in w["description"] if d["value"].startswith("CWE-")}
    cvss = None
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        if c.get("metrics", {}).get(key):
            m = min(c["metrics"][key], key=lambda x: x["type"] != "Primary")  # NVD's own score beats the CNA's
            d = m["cvssData"]
            cvss = {"version": d["version"], "score": d["baseScore"], "vector": d["vectorString"],
                    "severity": d.get("baseSeverity") or m.get("baseSeverity")}
            break
    products = set()
    for conf in c.get("configurations", []):
        for node in conf["nodes"]:
            products |= {":".join(m["criteria"].split(":")[3:5]) for m in node["cpeMatch"] if m["vulnerable"]}
    for a in c.get("affected", []):
        for d in a.get("affectedData", []):
            if _norm(d.get("product", "")) not in ("n_a", "unknown"):  # placeholders would link thousands of CVEs in the graph
                products.add(f"{_norm(d.get('vendor', ''))}:{_norm(d['product'])}")
    cwes = sorted(cwes, key=lambda s: int(s[4:]))
    return {
        "id": c["id"],
        "published": c["published"][:10],
        "status": c["vulnStatus"],
        "description": next((d["value"] for d in c["descriptions"] if d["lang"] == "en"), ""),
        "cwes": cwes,
        "vuln_class": vuln_class(cwes),
        "cvss": cvss,
        "products": sorted(products)[:50],
        "references": [r["url"] for r in c.get("references", [])][:15],
    }


def load_kev() -> dict[str, dict]:
    kev = json.loads((RAW / "kev.json").read_text())["vulnerabilities"]
    return {k["cveID"]: {"date_added": k["dateAdded"], "name": k["vulnerabilityName"],
                         "ransomware": k["knownRansomwareCampaignUse"], "action": k["requiredAction"]} for k in kev}


def load_epss(ids: set[str] | None = None) -> dict[str, tuple[float, float]]:
    with gzip.open(RAW / "epss.csv.gz", "rt") as f:
        next(f)  # "#model_version:...,score_date:..." comment line
        return {r["cve"]: (float(r["epss"]), float(r["percentile"]))
                for r in csv.DictReader(f) if ids is None or r["cve"] in ids}


def load_cwe_names() -> dict:
    xml = zipfile.ZipFile(RAW / "cwec.xml.zip").read(zipfile.ZipFile(RAW / "cwec.xml.zip").namelist()[0])
    return {f"CWE-{w.get('ID')}": w.get("Name") for w in ET.parse(io.BytesIO(xml)).getroot().iter()
            if w.tag.endswith("}Weakness")}


def minhash(texts: list[str], n_perm: int = 128, seed: int = 0) -> np.ndarray:
    """MinHash signatures over word 3-shingles. P(sig_a[i] == sig_b[i]) = Jaccard(a, b)."""
    P = (1 << 31) - 1  # Mersenne prime; a*x < 2^62 so int64 never overflows
    rng = np.random.default_rng(seed)
    a, b = rng.integers(1, P, n_perm), rng.integers(0, P, n_perm)
    sigs = np.empty((len(texts), n_perm), dtype=np.int64)
    for i, t in enumerate(texts):
        w = re.findall(r"\w+", t.lower()) or [""]
        sh = np.fromiter({zlib.crc32(" ".join(w[j:j + 3]).encode()) for j in range(max(1, len(w) - 2))}, np.int64)
        sigs[i] = ((a[:, None] * sh[None, :] + b[:, None]) % P).min(axis=1)
    return sigs


def near_dup_clusters(texts: list[str], threshold: float = 0.8, bands: int = 16) -> list[int]:
    """LSH banding + union-find. Returns, per text, the index of its cluster representative (lowest index)."""
    sig = minhash(texts)
    rows = sig.shape[1] // bands
    parent = list(range(len(texts)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for band in range(bands):
        head = {}
        for i in range(len(texts)):
            j = head.setdefault(sig[i, band * rows:(band + 1) * rows].tobytes(), i)
            # shortcut: each doc is compared only to its bucket's first member, so a few transitive
            # pairs can be missed; upgrade to all-pairs-per-bucket if exact clusters ever matter
            if j != i and (sig[i] == sig[j]).mean() >= threshold:
                ri, rj = find(i), find(j)
                parent[max(ri, rj)] = min(ri, rj)
    return [find(i) for i in range(len(texts))]


def build(years: list[int]) -> None:
    recs = []
    for y in years:
        with gzip.open(RAW / f"nvdcve-2.0-{y}.json.gz") as f:
            recs += [parse_nvd(v["cve"]) for v in json.load(f)["vulnerabilities"] if v["cve"]["vulnStatus"] != "Rejected"]
    recs = [r for r in recs if r["description"]]
    recs.sort(key=lambda r: (int(r["id"].split("-")[1]), int(r["id"].split("-")[2])))
    kev, epss = load_kev(), load_epss({r["id"] for r in recs})
    reps = near_dup_clusters([r["description"] for r in recs])
    for r, rep in zip(recs, reps):
        r["kev"] = kev.get(r["id"])
        r["epss"], r["epss_pct"] = epss.get(r["id"], (None, None))
        r["cluster"] = recs[rep]["id"]
    with gzip.open(DATASET, "wt", encoding="utf-8") as f:
        f.writelines(json.dumps(r, ensure_ascii=False) + "\n" for r in recs)
    (DATA / "cwe_names.json").write_text(json.dumps(load_cwe_names(), indent=0))
    print(f"wrote {len(recs)} records -> {DATASET}")


def stats() -> None:
    rs = records()
    n = len(rs)
    pct = lambda k: f"{k} ({100 * k / n:.1f}%)"
    sizes = Counter(r["cluster"] for r in rs)
    print(f"records: {n}  | years: {dict(sorted(Counter(r['id'][4:8] for r in rs).items()))}")
    print(f"status: {dict(Counter(r['status'] for r in rs).most_common())}")
    print(f"with CWE label: {pct(sum(r['vuln_class'] is not None for r in rs))} | with CVSS: {pct(sum(bool(r['cvss']) for r in rs))}")
    print(f"in CISA KEV: {sum(bool(r['kev']) for r in rs)} | with EPSS: {pct(sum(r['epss'] is not None for r in rs))}"
          f" | EPSS >= 0.1: {sum((r['epss'] or 0) >= 0.1 for r in rs)}")
    print(f"near-dup clusters (Jaccard>=0.8): {len(sizes)} | records in a cluster of size>1: "
          f"{pct(sum(s for s in sizes.values() if s > 1))} | largest: {sizes.most_common(1)[0][1]}")
    print("vuln_class:", dict(Counter(r["vuln_class"] for r in rs).most_common()))
    print("severity:", dict(Counter((r["cvss"] or {}).get("severity") for r in rs).most_common()))
    print("top vendors:", Counter(v for r in rs for v in {p.split(":")[0] for p in r["products"]}).most_common(15))
    lens = sorted(len(r["description"].split()) for r in rs)
    print(f"description words p50/p90/max: {lens[n // 2]}/{lens[int(n * .9)]}/{lens[-1]}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--years", type=int, nargs="+", default=[2025, 2026])
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()
    if not args.stats:
        download(args.years)
        build(args.years)
    stats()
