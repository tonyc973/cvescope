"""CVEScope: a CVE dataset + hybrid search + tool-using agents (AI-systems course project, FMI UniBuc)."""
import gzip
import json
import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
DATA = Path(os.getenv("CVESCOPE_DATA", ROOT / "data"))
DATASET = DATA / "cves.jsonl.gz"


@lru_cache(maxsize=1)
def records() -> list[dict]:
    with gzip.open(DATASET, "rt", encoding="utf-8") as f:
        return [json.loads(line) for line in f]


@lru_cache(maxsize=1)
def by_id() -> dict[str, dict]:
    return {r["id"]: r for r in records()}
