"""Step 4 - classification from the description only: vuln_class (12 classes) and CVSS severity.

Use case: ~13% of 2026 CVEs are still unanalyzed by NVD (no CWE / no CVSS yet) when they are published.
Baseline: TF-IDF + linear SVM. LLM: zero-shot with a structured (schema-validated) output.
"""
from typing import Literal

import numpy as np
from pydantic import BaseModel, Field
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import GroupShuffleSplit, ShuffleSplit
from sklearn.pipeline import make_pipeline
from sklearn.svm import LinearSVC

from .dataset import CLASSES
from .llm import MODEL, structured


def split(recs: list[dict], grouped: bool = True, seed: int = 0) -> tuple[list[dict], list[dict]]:
    """grouped=True keeps every near-duplicate cluster on one side, so templated descriptions
    (e.g. hundreds of 'The X plugin for WordPress is vulnerable to ...') cannot leak from train into test."""
    splitter = (GroupShuffleSplit if grouped else ShuffleSplit)(n_splits=1, test_size=0.2, random_state=seed)
    tr, te = next(splitter.split(recs, groups=[r["cluster"] for r in recs] if grouped else None))
    return [recs[i] for i in tr], [recs[i] for i in te]


def baseline(train: list[dict], label):
    model = make_pipeline(TfidfVectorizer(sublinear_tf=True, ngram_range=(1, 2), min_df=2, max_features=300_000),
                          LinearSVC(C=0.5))
    return model.fit([r["description"] for r in train], [label(r) for r in train])


CLASS_HELP = {
    "sqli": "SQL / NoSQL injection", "xss": "cross-site scripting", "csrf": "cross-site request forgery",
    "ssrf": "server-side request forgery", "deserialization": "unsafe deserialization of untrusted data",
    "path_file": "path traversal, symlink following, unrestricted file upload, DLL/search-path hijacking",
    "code_injection": "OS command / code / template / argument / file-inclusion injection",
    "memory": "buffer overflow, out-of-bounds read/write, use-after-free, NULL dereference, integer overflow",
    "access_control": "missing or broken authentication/authorization, privilege escalation, IDOR, hard-coded "
                      "credentials, wrong permissions",
    "info_leak": "exposure of sensitive information (logs, errors, cleartext, files)",
    "dos": "resource exhaustion, infinite loop, ReDoS, uncaught exception / crash without memory corruption",
    "other": "anything else (race conditions, crypto, input validation, open redirect, misconfiguration...)",
}
assert list(CLASS_HELP) == CLASSES


class Label(BaseModel):
    rationale: str = Field(description="one short sentence")  # generated before the label: a tiny chain of thought
    vuln_class: Literal[tuple(CLASSES)]


def llm_label(description: str, model: str = MODEL) -> Label:
    classes = "\n".join(f"- {c}: {h}" for c, h in CLASS_HELP.items())
    return structured([
        {"role": "system", "content": f"Classify the root-cause type of a software vulnerability.\n{classes}\n"
                                      "If several apply, pick the most specific weakness, not the consequence."},
        {"role": "user", "content": description},
    ], Label, model=model)


def macro_f1(y_true, y_pred) -> float:
    from sklearn.metrics import f1_score
    return round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 3)


def accuracy(y_true, y_pred) -> float:
    return round(float(np.mean(np.array(y_true) == np.array(y_pred))), 3)
