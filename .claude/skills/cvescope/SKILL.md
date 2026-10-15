---
name: cvescope
description: Lucru pe proiectul CVEScope (dataset de CVE-uri + căutare hibridă + agenți), proiectul de master FMI UniBuc la „Ingineria algoritmilor pentru sisteme AI”. Folosește-l când adaugi sau modifici cod, date, evaluări sau documentație în acest repo, când pregătești una din cele 3 prezentări, sau când construiești de la zero un proiect asemănător (dataset de vulnerabilități + RAG / agenți LLM).
---

# CVEScope: cum lucrezi bine pe acest proiect

## 1. Pentru ce se dă nota (citește înainte de orice schimbare)

Din fișa disciplinei, proiectul valorează **100%** din notă și se evaluează la **3 prezentări**. Criteriile:

- **calitatea dataset-ului și a sistemului**: acuratețe, performanță, inovație;
- **documentarea fiecărui pas**;
- **progresul față de roadmap**;
- **contribuția individuală**: fiecare membru trebuie să poată arăta ce a construit.

Componentele cerute explicit: dataset propriu (colectare, adnotare), căutare, clasificare, sumarizare, date sintetice, agenți, cod public pe GitHub și roadmap.

**Consecința:** orice schimbare trebuie să (1) corespundă unei componente de mai sus, (2) fie **măsurată** în `evaluate.py` și (3) fie **documentată** în `docs/`, cu bifa corespunzătoare în `docs/roadmap.md`. O funcționalitate fără cifre și fără documentație nu aduce puncte.

## 2. Harta repo-ului

| pas | fișier | ce face | comandă |
|---|---|---|---|
| 1 | `cvescope/dataset.py` | NVD feeds + KEV + EPSS + CWE → `data/cves.jsonl.gz`; `TAXONOMY` CWE→clasă; MinHash/LSH → `cluster` | `make data` |
| 2 | `cvescope/search.py` | BM25 propriu (CSC = index inversat), dense (`emb @ q`), RRF, filtre (mască), graf (`related`, `stats`) | `make index` |
| 3 | `cvescope/annotate.py` | set gold de 144: NVD vs. LLM, κ, arbitraj → `data/gold/gold.csv` | `make gold` |
| 4 | `cvescope/classify.py` | TF-IDF + LinearSVC; LLM cu ieșire structurată; separare pe grupuri | (prin `evaluate`) |
| 5 | `cvescope/agent.py` | bucla ReAct, 5 unelte, `fetch_live` (NVD API), verificarea `ungrounded` | `python -m cvescope.agent "..."` |
| 5b | `cvescope/summarize.py` | rezumat structurat al unui CVE | `python -m cvescope.summarize CVE-…` |
| 6 | `cvescope/team.py` | Orchestrator → cercetători în paralel → Writer → Judge, self-refine, trace | `python -m cvescope.team "..."` |
| 7 | `cvescope/synth.py` | întrebări sintetice validate → `data/synth/questions.jsonl` | `make synth` |
| 8 | `cvescope/evaluate.py` | toate metricile → `data/results.json` + `docs/results.md` (**generat; nu-l edita manual**) | `make eval` |
| – | `cvescope/llm.py` | client OpenAI-compatibil, cache SQLite (memo), cost și latență | – |
| – | `app.py` | Streamlit, 4 tab-uri | `make app` |
| – | `tests/test_core.py` | teste offline: LLM fals prin `monkeypatch`, fără cheie | `make test` |

Documentație: `README.md` (punct de intrare) și în `docs/`: `dataset_card.md`, `annotation_guidelines.md`, `methodology.md`, `evaluation.md`, `results.md` (generat), `related_work.md`, `roadmap.md`.

## 3. Reguli care nu se negociază

1. **Măsori înainte și după.** Dacă atingi căutarea, clasificarea sau agenții, rulează secțiunea relevantă (`python -m cvescope.evaluate retrieval|classification|agents`) și compară cu `data/results.json` din git. Pune diferența de cifre în mesajul de commit și în `docs/evaluation.md`. O regresie nu se ascunde: se explică.
2. **Fără scurgeri între train și test.** Orice separare se face pe `cluster` (`classify.split(grouped=True)`). Setul gold provine din partea de test. Întrebările sintetice folosesc doar CVE-uri fără aproape-duplicate.
3. **Nu suprascrie niciodată `data/gold/gold.csv`.** E muncă umană de adnotare. `annotate.py` îl creează o singură dată. Modificările se fac rând cu rând, cu `adjudication_note`.
4. **Ancorare.** Agentul citează doar ID-uri care apar în rezultatele uneltelor. Nu slăbi verificarea `ungrounded` și nu o scoate din UI sau din evaluare.
5. **Validare la granițe.** Textul produs de LLM e nesigur: se validează cu regex înainte de URL-uri (`get_cve`), iar ieșirile structurate trec prin pydantic. Uneltele agentului rămân read-only.
6. **Secrete.** Cheia stă doar în `.env` (gitignored). Niciodată în cod, commit-uri, loguri sau `data/`. Înainte de `git push`: `git grep -nE "sk-[A-Za-z0-9]{20,}"` trebuie să nu găsească nimic.
7. **Reproductibilitate.** Seed-uri fixe; cache-ul LLM salvează costul și latența odată cu răspunsul, deci reruările raportează aceleași cifre. Nu schimba cheia de cache (`memo`) fără motiv: invalidează tot cache-ul.
8. **Cod mic.** Biblioteca standard și dependențele deja existente; fără abstracții „pentru mai târziu”. Fiecare logică nouă primește un test offline în `tests/test_core.py`, în stilul celor existente. Scurtăturile se marchează `# shortcut: <limita>, <când se face upgrade>`.
9. **Terminologie onestă.** „Agent” înseamnă doar o componentă în care un LLM decide pași (Orchestrator, Cercetător, Judge). Un singur apel LLM sau o funcție deterministă nu e agent.
10. **Limba.** Documentația și UI-ul sunt în **română**; codul, comentariile și identificatorii în **engleză**.
11. **Atribuire.** Nota NVD (*This product uses data from the NVD API but is not endorsed or certified by the NVD.*) rămâne în README și în fișa dataset-ului.

## 4. Costuri și limite (verifică înainte de rulări mari)

- Embeddings: `text-embedding-3-small`, 512 dimensiuni. Tot dataset-ul costă ~$0,30 și durează ~15 minute (plafon de **1M tokeni/minut**). O cerere are **maximum 300k tokeni**, de aceea batch-ul e de 400.
- LLM implicit `gpt-4.1-mini`, judge `gpt-5-mini`. Prețurile sunt în `llm.PRICES`; un model necunoscut e contabilizat ca $0, deci adaugă-i prețul.
- Costuri măsurate: tot proiectul a costat $0,76 în apeluri LLM. O rulare a evaluării de agenți (12 întrebări × 2 sisteme + judge) costă ~$0,20 și durează 10–15 minute. Clasificarea pe gold cu `gpt-5-mini` costă $0,47 per 1.000 de CVE-uri. Reruările din cache sunt gratuite.
- Orice schimbare de prompt sau de descriere a unei unelte invalidează cache-ul pentru **toate** întrebările (descrierea uneltelor face parte din fiecare cerere). Rezultatele agenților variază cu ±1 întrebare între rulări, deci nu trage concluzii din diferențe de o întrebare.
- NVD API fără cheie: 5 cereri / 30 s. Folosește-l doar pentru căutări punctuale (`fetch_live`), niciodată pentru colectare în masă; pentru asta există feed-urile anuale.
- Rulează orice comandă cu `.venv/bin/python` (`make` face asta). Python-ul global de pe mașina de dezvoltare are `transformers` / pyOpenSSL stricate.
- Cheia API: `set -a; . ./.env; set +a` sau `load_dotenv` (deja în `cvescope/__init__.py`).

## 5. Rețete

**Unealtă nouă pentru agent**
1. Scrie funcția în `agent.py`, cu argumente JSON simple și rezultat compact (folosește `brief()`).
2. Adaug-o în `TOOLS` (`_tool(...)`) și în `FUNCS`.
3. Adaugă un test cu `chat` fals care o apelează.
4. Adaugă 1–2 întrebări în `data/eval_questions.jsonl` (cu `expect`).
5. Rulează `evaluate agents` și documentează în `methodology.md §5`.

**Alt an de date**
`python -m cvescope.dataset --years 2024 2025 2026`, apoi `make index`. Rulează `make index` **obligatoriu**: `Index` verifică cu un assert că embeddings și înregistrările au aceeași lungime. Actualizează cifrele din `dataset_card.md`.

**Taxonomia v2**
Modifici `TAXONOMY` din `dataset.py` și `CLASS_HELP` din `classify.py` (un assert verifică să aibă aceleași clase, în aceeași ordine), apoi `docs/annotation_guidelines.md`, apoi `make data`. Coloana `nvd_class` din gold rămâne cea din v1: recalculeaz-o într-o coloană nouă (`nvd_class_v2`), nu o suprascrie, și raportează ambele valori.

**Alt model sau furnizor**
Setează `CVESCOPE_MODEL` / `CVESCOPE_JUDGE_MODEL`. Pentru OpenRouter sau Ollama, setează și `OPENAI_BASE_URL`. Adaugă prețul în `PRICES` și modelul în `GOLD_MODELS`, dacă intră în comparație.

**Metrică nouă**
Adaug-o într-o funcție de secțiune din `evaluate.py` (dicționar de dicționare → tabelul se generează singur). Explică-o în `docs/evaluation.md`.

## 6. Capcane deja întâlnite

- Feed-urile NVD sunt grupate după **anul din ID**, nu după data publicării.
- Peste 13% din CVE-urile din 2026 sunt neanalizate (fără CWE sau CVSS). De aici cazul de utilizare pentru clasificator.
- Produsele `n/a` / `unknown` din blocul `affected` leagă mii de CVE-uri în graf. Sunt filtrate în `parse_nvd`; nu le reintroduce.
- `oracle` vs. `oracle_corporation`: normalizarea vendorilor e imperfectă (vezi roadmap).
- LLM-ul de clasificare etichetează **consecința** (RCE → `code_injection`) în loc de cauză. Asta e principala sursă de erori.
- Întrebările sintetice sunt parafraze scrise de LLM: pe ele dense bate hibridul (MRR 0,881 vs. 0,868). Nu schimba modul implicit doar pe baza lor. Interogările reale conțin ID-uri, versiuni și nume de funcții, unde BM25 contează.
- `search_cves` întoarce doar top k. Întrebările de tip „câte / listează toate” trebuie să ajungă la `cve_stats`, care listează toate ID-urile când sunt ≤ 30. Judge-ul NU poate prinde un răspuns incomplet dacă și dovezile sunt incomplete; doar `expected_id_recall` îl prinde.
- Modelele `gpt-5*` nu acceptă `temperature`. Codul nu-l setează; determinismul vine din cache.
- `st.chat_input` e folosit într-un tab; necesită Streamlit ≥ 1.31.

## 7. Prezentările

- **P1 (pitch):** problema (volumul de CVE-uri, backlog-ul NVD), literatura (`related_work.md`), arhitectura (diagrama mermaid din `methodology.md`), roadmap-ul cu cine ce deține. Fiecare membru are cel puțin un slide.
- **P2 (dataset + v1):** cifrele din `dataset_card.md`, aproape-duplicatele (14,3%) și de ce contează, κ = 0,818 și ce am învățat la arbitraj, demo live: căutare, CVE, agent cu trace.
- **P3 (final):** tabelele din `results.md`. Accent pe trei comparații: (a) separare aleatoare vs. pe grupuri (scurgere), (b) baseline vs. LLM-uri (calitate / cost / latență), (c) agent simplu vs. multi-agent (calitate vs. cost). Apoi limitările, cinstit.
- Fiecare cifră de pe slide trebuie să existe în `docs/results.md` sau `dataset_card.md`, ca să poată fi reprodusă.

## 8. Definiția lui „gata”

- [ ] `make test` trece
- [ ] secțiunea de evaluare atinsă a fost rerulată, iar `docs/results.md` a fost regenerat
- [ ] `docs/` actualizat: metodologie, plus interpretarea în `evaluation.md` și bifa în `roadmap.md`
- [ ] cifrele din `README.md` sunt aceleași cu cele din `results.md`
- [ ] niciun secret în diff; `data/raw`, `embeddings.npy` și `llm_cache.sqlite` nu sunt adăugate în git
- [ ] mesajul de commit spune *ce* s-a schimbat și *cu cât* s-a mișcat metrica

## 9. Dacă reconstruiești un proiect similar de la zero

Ordinea care minimizează munca aruncată (fiecare pas are un criteriu de acceptare):

1. **Date:** sursă oficială în masă (feed-uri, nu API paginat), un parser comun, statistici. *Acceptare:* fișa dataset-ului completată cu cifre.
2. **Deduplicare și separare pe grupuri.** *Acceptare:* procentul de aproape-duplicate e cunoscut.
3. **Set gold mic, stratificat, cu ghid scris și κ.** *Acceptare:* κ raportat și dezacordurile arbitrate cu motiv.
4. **Căutare lexicală, apoi semantică, apoi RRF**, evaluate pe întrebări sintetice validate. *Acceptare:* tabel Recall@k / MRR pentru toate cele 3 metode.
5. **Baseline clasic înaintea LLM-ului.** *Acceptare:* LLM-ul se compară cu el pe același gold, cu cost și latență.
6. **Un singur agent cu unelte și verificare deterministă de ancorare**, apoi multi-agent doar dacă se măsoară un câștig. *Acceptare:* tabel single vs. multi.
7. **UI la final** și documentație la fiecare pas, nu la sfârșit.
