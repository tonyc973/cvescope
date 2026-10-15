PY = .venv/bin/python

setup:            ## virtualenv + dependencies
	uv venv .venv --python 3.12 && uv pip install --python $(PY) -r requirements.txt
data:             ## download NVD 2025+2026, CISA KEV, EPSS, CWE -> data/cves.jsonl.gz (~1 min)
	$(PY) -m cvescope.dataset
index:            ## embeddings for dense search -> data/embeddings.npy (~$0.30, ~15 min at 1M TPM)
	$(PY) -m cvescope.search --build
gold:             ## gold set: NVD label vs LLM label + adjudication -> data/gold/gold.csv
	$(PY) -m cvescope.annotate
synth:            ## synthetic search questions -> data/synth/questions.jsonl
	$(PY) -m cvescope.synth
eval:             ## all evaluations -> data/results.json + docs/results.md
	$(PY) -m cvescope.evaluate
app:              ## Streamlit UI
	$(PY) -m streamlit run app.py
test:             ## offline tests, no API key needed
	$(PY) -m pytest -q

.PHONY: setup data index gold synth eval app test
