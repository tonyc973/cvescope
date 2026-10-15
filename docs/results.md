# Rezultate (generat de `python -m cvescope.evaluate`)

Model: `gpt-4.1-mini`, judge: `gpt-5-mini`. Metodologia: [evaluation.md](evaluation.md).

## classification

| | n_test | accuracy | macro_f1 | usd_per_1k | sec_per_call |
|---|---|---|---|---|---|
| vuln_class, random split | 21877 | 0.881 | 0.88 |  |  |
| vuln_class, grouped split | 21876 | 0.879 | 0.879 |  |  |
| severity, grouped split | 22727 | 0.695 | 0.553 |  |  |
| gold: NVD/CNA label | 144 | 0.951 | 0.948 |  |  |
| gold: TF-IDF + LinearSVC | 144 | 0.882 | 0.885 |  |  |
| gold: LLM gpt-4.1-nano | 144 | 0.889 | 0.888 | 0.053 | 0.75 |
| gold: LLM gpt-4.1-mini | 144 | 0.875 | 0.857 | 0.215 | 0.95 |
| gold: LLM gpt-5-mini | 144 | 0.938 | 0.936 | 0.472 | 2.29 |

## summaries

| | n | grounded | complete | useful | passed | usd_per_summary | sec_per_summary |
|---|---|---|---|---|---|---|---|
| summaries of CISA KEV CVEs | 15 | 4.867 | 4.733 | 4.333 | 1.0 | 0.001 | 2.423 |

## retrieval

| | n | recall@1 | recall@5 | recall@10 | mrr@10 |
|---|---|---|---|---|---|
| bm25 | 191.0 | 0.738 | 0.895 | 0.937 | 0.802 |
| dense | 191.0 | 0.822 | 0.974 | 0.979 | 0.881 |
| hybrid | 191.0 | 0.801 | 0.948 | 0.979 | 0.868 |

## agents

| | n | grounded | complete | useful | passed | ungrounded_ids | expected_id_recall | usd | llm_seconds | rounds | first_draft_min_score |
|---|---|---|---|---|---|---|---|---|---|---|---|
| single agent | 12 | 4.833 | 4.667 | 4.5 | 0.833 | 0.0 | 0.944 | 0.002 | 5.364 | None | None |
| orchestrator + judge | 12 | 4.75 | 4.417 | 4.333 | 0.917 | 0.0 | 0.958 | 0.014 | 55.878 | 1.5 | 3.667 |
