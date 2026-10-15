"""Step 1 - dataset: download NVD + CISA KEV + EPSS + CWE, normalize, label, near-dedup.

    python -m cvescope.dataset --years 2025 2026      # download (cached in data/raw) + build data/cves.jsonl.gz
    python -m cvescope.dataset --stats                # print the dataset card numbers
"""
import argparse
import csv
import gzip
import json
import re
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections import Counter

import numpy as np
from scipy.sparse import coo_matrix
from scipy.sparse.csgraph import connected_components

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
CWE_TO_CLASS = {f"CWE-{number}": cls for cls, numbers in TAXONOMY.items() for number in numbers}


def vuln_class(cwes: list[str]) -> str | None:
    """None = no usable CWE (unlabeled, e.g. not yet analyzed by NVD)."""
    if not cwes:
        return None
    found = {CWE_TO_CLASS.get(cwe, "other") for cwe in cwes}
    for cls in CLASSES:  # CLASSES goes from most to least specific
        if cls in found:
            return cls


def download(years: list[int]) -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    urls = {f"nvdcve-2.0-{y}.json.gz": NVD_FEED.format(y) for y in years} | SOURCES
    for name, url in urls.items():
        if not (RAW / name).exists():
            print("download", url)
            req = urllib.request.Request(url, headers={"User-Agent": "cvescope (student project)"})
            (RAW / name).write_bytes(urllib.request.urlopen(req, timeout=120).read())


def _norm(s: str) -> str:
    """'Acme Inc.' -> 'acme_inc' (same style as CPE names)."""
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_") or "n_a"


# --- parsing one NVD record --------------------------------------------------------------------

def _description(cve: dict) -> str:
    for d in cve["descriptions"]:
        if d["lang"] == "en":
            return d["value"]
    return ""


def _cwes(cve: dict) -> list[str]:
    cwes = set()
    for weakness in cve.get("weaknesses", []):
        for d in weakness["description"]:
            if d["value"].startswith("CWE-"):  # skips the placeholders NVD-CWE-noinfo / NVD-CWE-Other
                cwes.add(d["value"])
    return sorted(cwes, key=lambda cwe: int(cwe[4:]))  # numeric order: CWE-79 before CWE-352


def _cvss(cve: dict) -> dict | None:
    """The newest CVSS version present; for that version, NVD's own score ("Primary") beats the CNA's."""
    for version in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(version)
        if not metrics:
            continue
        primary = [m for m in metrics if m["type"] == "Primary"]
        m = (primary or metrics)[0]
        data = m["cvssData"]
        return {"version": data["version"], "score": data["baseScore"], "vector": data["vectorString"],
                "severity": data.get("baseSeverity") or m.get("baseSeverity")}  # v2 keeps severity outside cvssData
    return None


def _products(cve: dict) -> list[str]:
    """'vendor:product' strings, from NVD's CPE matches and from the CNA's 'affected' block."""
    products = set()
    for config in cve.get("configurations", []):
        for node in config["nodes"]:
            for match in node["cpeMatch"]:
                if match["vulnerable"]:
                    parts = match["criteria"].split(":")  # cpe:2.3:a:apache:log4j:2.14.1:*:...
                    products.add(f"{parts[3]}:{parts[4]}")
    for affected in cve.get("affected", []):
        for item in affected.get("affectedData", []):
            product = _norm(item.get("product", ""))
            if product not in ("n_a", "unknown"):  # placeholders would link thousands of CVEs in the graph
                products.add(f"{_norm(item.get('vendor', ''))}:{product}")
    return sorted(products)[:50]


def parse_nvd(cve: dict) -> dict:
    """One NVD API 2.0 'cve' object -> our flat record. Same schema for the yearly feeds and the live API."""
    cwes = _cwes(cve)
    return {
        "id": cve["id"],
        "published": cve["published"][:10],
        "status": cve["vulnStatus"],
        "description": _description(cve),
        "cwes": cwes,
        "vuln_class": vuln_class(cwes),
        "cvss": _cvss(cve),
        "products": _products(cve),
        "references": [r["url"] for r in cve.get("references", [])][:15],
    }


# --- enrichment sources ------------------------------------------------------------------------

def load_kev() -> dict[str, dict]:
    kev = json.loads((RAW / "kev.json").read_text())["vulnerabilities"]
    return {k["cveID"]: {"date_added": k["dateAdded"], "name": k["vulnerabilityName"],
                         "ransomware": k["knownRansomwareCampaignUse"], "action": k["requiredAction"]} for k in kev}


def load_epss(ids: set[str] | None = None) -> dict[str, tuple[float, float]]:
    """CVE id -> (EPSS probability, percentile)."""
    out = {}
    with gzip.open(RAW / "epss.csv.gz", "rt") as f:
        next(f)  # first line is a comment: "#model_version:...,score_date:..."
        for row in csv.DictReader(f):
            if ids is None or row["cve"] in ids:
                out[row["cve"]] = (float(row["epss"]), float(row["percentile"]))
    return out


def load_cwe_names() -> dict:
    with zipfile.ZipFile(RAW / "cwec.xml.zip") as z:
        root = ET.fromstring(z.read(z.namelist()[0]))
    # tags carry a namespace: "{http://cwe.mitre.org/cwe-7}Weakness"
    return {f"CWE-{w.get('ID')}": w.get("Name") for w in root.iter() if w.tag.endswith("}Weakness")}


# --- near-duplicate detection: MinHash + LSH ---------------------------------------------------

def shingles(text: str) -> set[int]:
    """The text as a set of hashed word 3-grams ('shingles')."""
    words = re.findall(r"\w+", text.lower()) or [""]
    return {zlib.crc32(" ".join(words[i:i + 3]).encode()) for i in range(max(1, len(words) - 2))}


def minhash(texts: list[str], n_perm: int = 128, seed: int = 0) -> np.ndarray:
    """One signature of n_perm numbers per text. Key property: two signatures agree on a position
    with probability = Jaccard similarity of the two shingle sets."""
    P = (1 << 31) - 1  # a prime; a * x < 2^62, so int64 never overflows
    rng = np.random.default_rng(seed)
    a, b = rng.integers(1, P, n_perm), rng.integers(0, P, n_perm)  # n_perm random hash functions (a*x + b) % P
    signatures = np.empty((len(texts), n_perm), dtype=np.int64)
    for i, text in enumerate(texts):
        x = np.fromiter(shingles(text), np.int64)
        hashes = (a[:, None] * x[None, :] + b[:, None]) % P  # row h = hash function h applied to every shingle
        signatures[i] = hashes.min(axis=1)  # keep only the smallest hash of each function
    return signatures


def near_dup_clusters(texts: list[str], threshold: float = 0.8, bands: int = 16) -> list[int]:
    """Returns, for every text, the index of its cluster representative (the lowest index in the cluster)."""
    sig = minhash(texts)
    rows = sig.shape[1] // bands
    pairs = []
    # LSH: cut each signature into bands; texts with an identical band land in the same bucket
    for band in range(bands):
        first_in_bucket = {}
        for i in range(len(texts)):
            j = first_in_bucket.setdefault(sig[i, band * rows:(band + 1) * rows].tobytes(), i)
            # shortcut: each doc is compared only to its bucket's first member, so a few transitive
            # pairs can be missed; upgrade to all-pairs-per-bucket if exact clusters ever matter
            if j != i and (sig[i] == sig[j]).mean() >= threshold:
                pairs.append((i, j))
    # a cluster = a connected component of the graph whose edges are the similar pairs
    i, j = np.array(pairs, dtype=np.int64).reshape(-1, 2).T
    graph = coo_matrix((np.ones(len(i)), (i, j)), shape=(len(texts), len(texts)))
    _, component = connected_components(graph, directed=False)
    first_of = {}
    return [first_of.setdefault(c, pos) for pos, c in enumerate(component)]


# --- build + statistics ------------------------------------------------------------------------

def _id_order(cve_id: str) -> tuple[int, int]:
    """'CVE-2026-1603' -> (2026, 1603): numeric order, so CVE-2026-999 comes before CVE-2026-1000."""
    _, year, number = cve_id.split("-")
    return int(year), int(number)


def build(years: list[int]) -> None:
    recs = []
    for y in years:
        with gzip.open(RAW / f"nvdcve-2.0-{y}.json.gz") as f:
            for item in json.load(f)["vulnerabilities"]:
                if item["cve"]["vulnStatus"] != "Rejected":
                    recs.append(parse_nvd(item["cve"]))
    recs = [r for r in recs if r["description"]]
    recs.sort(key=lambda r: _id_order(r["id"]))

    kev, epss = load_kev(), load_epss({r["id"] for r in recs})
    representatives = near_dup_clusters([r["description"] for r in recs])
    for r, rep in zip(recs, representatives):
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

    def share(count: int) -> str:
        return f"{count} ({100 * count / n:.1f}%)"

    cluster_sizes = Counter(r["cluster"] for r in rs)
    in_clusters = sum(size for size in cluster_sizes.values() if size > 1)
    years = dict(sorted(Counter(r["id"][4:8] for r in rs).items()))
    vendors = Counter(v for r in rs for v in {p.split(":")[0] for p in r["products"]})  # count each CVE once
    words = sorted(len(r["description"].split()) for r in rs)

    print(f"records: {n}  | years: {years}")
    print(f"status: {dict(Counter(r['status'] for r in rs).most_common())}")
    print(f"with CWE label: {share(sum(r['vuln_class'] is not None for r in rs))}"
          f" | with CVSS: {share(sum(bool(r['cvss']) for r in rs))}")
    print(f"in CISA KEV: {sum(bool(r['kev']) for r in rs)} | with EPSS: {share(sum(r['epss'] is not None for r in rs))}"
          f" | EPSS >= 0.1: {sum((r['epss'] or 0) >= 0.1 for r in rs)}")
    print(f"near-dup clusters (Jaccard>=0.8): {len(cluster_sizes)} | records in a cluster of size>1: "
          f"{share(in_clusters)} | largest: {cluster_sizes.most_common(1)[0][1]}")
    print("vuln_class:", dict(Counter(r["vuln_class"] for r in rs).most_common()))
    print("severity:", dict(Counter((r["cvss"] or {}).get("severity") for r in rs).most_common()))
    print("top vendors:", vendors.most_common(15))
    print(f"description words p50/p90/max: {words[n // 2]}/{words[int(n * .9)]}/{words[-1]}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--years", type=int, nargs="+", default=[2025, 2026])
    ap.add_argument("--stats", action="store_true")
    args = ap.parse_args()
    if not args.stats:
        download(args.years)
        build(args.years)
    stats()
