"""LLM access: one OpenAI-compatible client + SQLite memoization + token/cost accounting.

Works with OpenAI, OpenRouter or a local Ollama: the openai SDK reads OPENAI_BASE_URL / OPENAI_API_KEY.
"""
import hashlib
import json
import os
import sqlite3
import threading
import time
from collections import Counter

import numpy as np
from openai import OpenAI
from pydantic import BaseModel

from . import DATA

MODEL = os.getenv("CVESCOPE_MODEL", "gpt-4.1-mini")
JUDGE_MODEL = os.getenv("CVESCOPE_JUDGE_MODEL", "gpt-5-mini")  # other family than MODEL: limits self-preference bias
EMBED_MODEL, EMBED_DIM = "text-embedding-3-small", 512
# USD per 1M tokens (input, output), from the OpenAI pricing page; unknown models are counted as 0.
PRICES = {"gpt-4.1": (2.0, 8.0), "gpt-4.1-mini": (0.4, 1.6), "gpt-4.1-nano": (0.1, 0.4),
          "gpt-5-mini": (0.25, 2.0), "gpt-5-nano": (0.05, 0.4), "text-embedding-3-small": (0.02, 0)}
USAGE = Counter()  # calls, cache_hits, in/out tokens, seconds, usd - for this process (cache hits included)

DATA.mkdir(parents=True, exist_ok=True)
_db = sqlite3.connect(DATA / "llm_cache.sqlite", check_same_thread=False)
_db.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT)")
_lock = threading.Lock()
_client = None


def client() -> OpenAI:
    global _client
    _client = _client or OpenAI(max_retries=8)  # lazy: importing the package must not need an API key
    return _client


def memo(payload: dict, fn):
    """Memoization: an identical request is paid once. fn() -> (value, usage). Cost and latency are stored
    with the value, so a cached rerun of an evaluation reports the same numbers, for free."""
    key = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()
    with _lock:
        row = _db.execute("SELECT value FROM cache WHERE key=?", (key,)).fetchone()
    if row:
        rec = json.loads(row[0])
        USAGE["cache_hits"] += 1
    else:
        t = time.time()
        value, usage = fn()
        p_in, p_out = PRICES.get(payload["model"], (0, 0))
        out = getattr(usage, "completion_tokens", 0) or 0
        rec = {"value": value, "in": usage.prompt_tokens, "out": out, "seconds": round(time.time() - t, 3),
               "usd": (usage.prompt_tokens * p_in + out * p_out) / 1e6}
        with _lock:
            _db.execute("INSERT OR REPLACE INTO cache VALUES (?, ?)", (key, json.dumps(rec)))
            _db.commit()
    with _lock:
        USAGE.update({"calls": 1, "in": rec["in"], "out": rec["out"], "seconds": rec["seconds"], "usd": rec["usd"]})
    return rec["value"]


def chat(messages: list[dict], model: str = MODEL, tools: list | None = None) -> dict:
    """Returns the assistant message as a dict (content and/or tool_calls), ready to append to `messages`."""
    def call():
        r = client().chat.completions.create(model=model, messages=messages, **({"tools": tools} if tools else {}))
        return r.choices[0].message.model_dump(exclude_none=True, include={"role", "content", "tool_calls"}), r.usage
    return memo({"model": model, "messages": messages, "tools": tools}, call)


def structured(messages: list[dict], schema: type[BaseModel], model: str = MODEL) -> BaseModel:
    """Structured output: the API is constrained to the JSON schema, pydantic validates it again on our side."""
    def call():
        r = client().chat.completions.parse(model=model, messages=messages, response_format=schema)
        return r.choices[0].message.content, r.usage
    raw = memo({"model": model, "messages": messages, "schema": schema.model_json_schema()}, call)
    return schema.model_validate_json(raw)


def embed(texts: list[str]) -> np.ndarray:
    out = []
    for i in range(0, len(texts), 400):  # API cap: 300k tokens per request
        r = client().embeddings.create(model=EMBED_MODEL, input=[t[:8000] for t in texts[i:i + 400]],
                                       dimensions=EMBED_DIM)
        USAGE["usd"] += r.usage.prompt_tokens * PRICES[EMBED_MODEL][0] / 1e6
        out += [d.embedding for d in r.data]
        if len(texts) > 1000:
            print(f"\rembedded {len(out)}/{len(texts)}", end="", flush=True)
    return np.array(out, dtype=np.float32)


def embed_query(q: str) -> np.ndarray:
    def call():
        r = client().embeddings.create(model=EMBED_MODEL, input=[q], dimensions=EMBED_DIM)
        return r.data[0].embedding, r.usage
    v = memo({"model": EMBED_MODEL, "dim": EMBED_DIM, "q": q}, call)
    return np.array(v, dtype=np.float32)
