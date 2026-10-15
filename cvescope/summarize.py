"""Step 5b - summarization: a structured, grounded briefing of one CVE for a non-specialist.

    python -m cvescope.summarize CVE-2026-21589
"""
import json
import sys

from pydantic import BaseModel, Field

from .llm import MODEL, structured


class Summary(BaseModel):
    tldr: str = Field(description="1-2 plain sentences, no jargon")
    affected: str = Field(description="products / versions, as given in the record")
    attacker_needs: str = Field(description="preconditions: network access, login, user interaction")
    impact: str
    what_to_do: str = Field(description="concrete next step; mention CISA KEV deadline/action if present")


def evidence(r: dict) -> str:
    keep = ("id", "published", "description", "cwes", "cvss", "products", "kev", "epss", "references")
    return json.dumps({k: r.get(k) for k in keep}, ensure_ascii=False)


def summarize(r: dict, lang: str = "Romanian", model: str = MODEL) -> Summary:
    return structured([
        {"role": "system", "content": f"Explain a vulnerability record to a busy sysadmin, in {lang}. Use ONLY facts "
                                      "from the record; write 'unknown' when the record does not say."},
        {"role": "user", "content": evidence(r)},
    ], Summary, model=model)


if __name__ == "__main__":
    from .agent import get_cve
    print(summarize(get_cve(sys.argv[1])).model_dump_json(indent=1))
