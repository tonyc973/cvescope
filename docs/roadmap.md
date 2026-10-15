# Roadmap

Proiect în echipă de 4. Nota se acordă individual, după contribuție, deci **fiecare membru deține o componentă** și o prezintă.

| rol (propunere) | deține | fișiere |
|---|---|---|
| Date și adnotare | colectare, curățare, deduplicare, ghid de adnotare, set gold | `dataset.py`, `annotate.py`, `docs/dataset_card.md`, `docs/annotation_guidelines.md` |
| Căutare și evaluare | BM25, embeddings, RRF, graf, date sintetice, metrici | `search.py`, `synth.py`, `evaluate.py` |
| Clasificare | baseline, LLM, comparație de modele (calitate / cost) | `classify.py` |
| Agenți și aplicație | agent cu unelte, multi-agent, judge, UI | `agent.py`, `team.py`, `summarize.py`, `app.py` |

## Prezentarea 1: propunere, literatură, roadmap

- [x] Problema și motivația ([dataset_card.md §1](dataset_card.md))
- [x] Studiul literaturii ([related_work.md](related_work.md))
- [x] Arhitectura propusă ([methodology.md](methodology.md))
- [x] Acest roadmap
- [ ] Slide-uri: câte unul pe membru, pentru componenta pe care o deține

## Prezentarea 2: dataset-ul și prima versiune funcțională

- [x] Dataset: 116.902 CVE-uri, NVD + KEV + EPSS + CWE, clustere de aproape-duplicate
- [x] Fișa dataset-ului și ghidul de adnotare
- [x] Set gold de 144 de CVE-uri, adnotare dublă, κ = 0,818, arbitraj
- [x] Căutare hibridă (BM25 + dense + RRF) cu filtre, graf, agregate
- [x] Agent cu 5 unelte, inclusiv extragere live din NVD API, și verificarea ancorării
- [x] Aplicație Streamlit cu 4 tab-uri
- [ ] **Un membru al echipei verifică cele 24 de arbitraje făcute cu asistență AI** (`data/gold/gold.csv`, coloana `adjudication_note`)
- [ ] Taxonomia v2: adăugăm CWE-369/407/457/602/822 (vezi ghidul), apoi `make data` și recalcularea acordului
- [ ] Demo live pregătit: 3 întrebări din `data/eval_questions.jsonl` + trace-ul multi-agent

## Prezentarea 3: sistemul final, evaluare, limitări

- [x] Evaluare: regăsire (Recall@k, MRR), clasificare (separare aleatoare vs. pe grupuri, set gold, 3 LLM-uri), agenți (single vs. multi-agent, judge, ID-uri neancorate, cost) → [results.md](results.md)
- [ ] Rezumat: antet determinist (ID, CVSS, KEV, EPSS) + câmpul `fixed_versions`, cerute de feedback-ul judge-ului ([evaluation.md §2b](evaluation.md#2b-sumarizare))
- [ ] Prompt few-shot pentru clasificatorul LLM, cu capcanele „cauză vs. consecință” găsite la arbitraj
- [ ] **Separare temporală**: antrenare pe 2025, testare pe 2026. E cel mai realist scenariu (V2W-BERT arată o scădere de la 97% la 94%)
- [ ] Clasificatorul aplicat pe cele 7.521 de CVE-uri fără CWE, cu eticheta `predicted_class` vizibilă în căutare
- [ ] Set de evaluare pentru agenți extins la ≥ 50 de întrebări, plus evaluare umană pe un eșantion, ca să calibrăm judge-ul (acordul om–judge)
- [ ] Set de interogări reale / „keyword” (ID-uri, versiuni, nume de funcții) pe lângă parafrazele sintetice, plus RRF ponderat: pe parafraze, dense bate hibridul
- [ ] Re-ranking cu un cross-encoder peste top-50 RRF
- [ ] Normalizarea produselor cu dicționarul oficial CPE (`oracle` = `oracle_corporation`)
- [ ] Publicarea dataset-ului pe Hugging Face Hub (cu fișa dataset-ului ca README)

## Idei pentru mai târziu

- Etichete multi-label: un CVE poate avea un lanț de slăbiciuni
- Embeddings locale (bge-small) pe GPU, pentru a funcționa offline
- Actualizare zilnică incrementală (NVD „modified” feed + KEV + EPSS)
