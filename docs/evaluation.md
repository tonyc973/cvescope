# Evaluare

Toate cifrele de aici sunt generate de `python -m cvescope.evaluate` → [results.md](results.md) și `data/results.json`. Costul și latența sunt cele ale primei rulări, fără cache. Ele sunt salvate împreună cu fiecare răspuns, deci o rerulare din cache raportează aceleași valori și nu costă nimic.

## 1. Regăsire (căutare)

**Set:** 191 de întrebări sintetice (`data/synth/questions.jsonl`). Fiecare are un singur CVE-țintă, fără aproape-duplicate. Am generat 200 și validarea a respins 9.
**Metrici:**

- **Recall@k:** în ce procent din întrebări ținta apare în primele k rezultate;
- **MRR@10:** media lui 1/poziție, cu 0 dacă ținta nu e în top 10.

Căutarea rulează peste toate cele 116.902 CVE-uri, fără filtre.

| metodă | Recall@1 | Recall@5 | Recall@10 | MRR@10 |
|---|---|---|---|---|
| BM25 (lexical) | 0,738 | 0,895 | 0,937 | 0,802 |
| dense (embeddings) | **0,822** | **0,974** | **0,979** | **0,881** |
| hibrid (RRF) | 0,801 | 0,948 | **0,979** | 0,868 |

**Interpretare:**

- **Pe acest set, căutarea dense singură câștigă.** Hibridul o egalează doar la Recall@10. RRF dă aceeași greutate ambelor clasamente, iar când unul e vizibil mai slab (BM25, cu 8 puncte mai jos la Recall@1), îl trage în jos pe celălalt.
- **Bias-ul setului:** întrebările sunt *parafraze scrise de un LLM*, deci stilul lor seamănă cu ce prind embeddings bine. Interogările reale conțin des tokeni exacți: ID-uri, versiuni, nume de funcții, coduri de produs. Pe ele potrivirea lexicală e esențială, iar embeddings le ratează des.
- **Decizie:** modul implicit rămâne **hibrid**, pentru robustețe la interogări cu tokeni exacți, cu prețul a ~1 punct la MRR pe parafraze. Pentru agent contează Recall@5–10, fiindcă citește top 8, unde hibridul e la 0,948–0,979. Roadmap: un set de interogări reale sau „keyword” și RRF ponderat.
- Toate metodele găsesc ținta în top 10 în ≥ 94% din cazuri, pe 116.902 documente.

## 2. Clasificare

**Ținte:** `vuln_class` (12 clase) și severitatea CVSS (4 clase), prezise **doar din descriere**.
**Metrici:** acuratețe și **macro-F1**. Macro-F1 e media F1 pe clase, deci clasele rare cântăresc la fel de mult ca cele frecvente.

**Seturi:**

- *split aleator* vs. *split pe grupuri*, cu 80/20 din cele 109.381 de CVE-uri etichetate. Diferența dintre cele două măsoară scurgerea prin descrieri șablon.
- *gold*: 144 de CVE-uri arbitrate ([ghid](annotation_guidelines.md)). Pe acest set comparăm eticheta oficială NVD/CNA, baseline-ul și trei LLM-uri.

> Atenție: `gpt-4.1-mini` a fost și adnotatorul B la construirea setului gold. Pe rândurile în care a fost de acord cu NVD, eticheta gold coincide cu a lui, deci scorul lui e ușor avantajat. `gpt-4.1-nano` și `gpt-5-mini` nu au participat la adnotare.

### Rezultate

| model | set | acuratețe | macro-F1 | cost / 1.000 CVE | sec / CVE |
|---|---|---|---|---|---|
| TF-IDF + LinearSVC | split aleator (n = 21.877) | 0,881 | 0,880 | ~0 | < 0,001 |
| TF-IDF + LinearSVC | **split pe grupuri** (n = 21.876) | **0,879** | **0,879** | ~0 | < 0,001 |
| TF-IDF + LinearSVC, *severitate* | split pe grupuri (n = 22.727) | 0,695 | 0,553 | ~0 | < 0,001 |
| eticheta oficială NVD/CNA | gold (n = 144) | 0,951 | 0,948 | – | – |
| TF-IDF + LinearSVC | gold | 0,882 | 0,885 | ~0 | < 0,001 |
| LLM `gpt-4.1-nano` | gold | 0,889 | 0,888 | $0,05 | 0,75 |
| LLM `gpt-4.1-mini` | gold | 0,875 | 0,857 | $0,22 | 0,95 |
| LLM `gpt-5-mini` | gold | **0,938** | **0,936** | $0,47 | 2,29 |

### Interpretare

- **Scurgerea prin aproape-duplicate are un efect mic aici**: +0,2 puncte procentuale la split aleator. Descrierile șablon conțin aproape literal numele clasei („…is vulnerable to Stored Cross-Site Scripting…”), deci sunt ușor de clasificat chiar și fără să fi văzut șablonul. Raportăm totuși split-ul pe grupuri. Pe sarcini în care șablonul *nu* conține eticheta (de exemplu produsul sau severitatea), efectul poate fi mare.
- **Severitatea doar din descriere e grea** (macro-F1 0,553). CVSS depinde de detalii care de multe ori nu sunt în text: privilegiile necesare, scope-ul, impactul exact. Clasa LOW e rară și slab recunoscută. Rezultatul e consistent cu motivația CVSS-BERT, care prezice fiecare metrică separat.
- **Pe gold, `gpt-5-mini` (0,938) se apropie de eticheta oficială (0,951).** Celelalte trei sisteme sunt la 0,875–0,889. Cu n = 144, intervalul de încredere de 95% pentru o acuratețe de ~0,88 este de aproximativ **±5 puncte**. Diferențele dintre nano, mini și baseline **nu sunt semnificative**, iar avantajul lui `gpt-5-mini` e la limită. Pentru o concluzie fermă e nevoie de un set gold mai mare (vezi roadmap).
- **`gpt-4.1-mini` nu e mai bun decât `gpt-4.1-nano`**, deși costă de 4 ori mai mult și a fost avantajat ca adnotator B. Erorile pe gold, numărate pe tipuri, arată profiluri diferite:

  | model | erori | cea mai frecventă confuzie |
  |---|---|---|
  | `gpt-4.1-mini` | 18 | etichetează **consecința**: → `access_control` (9×), → `code_injection` (4×) |
  | `gpt-4.1-nano` | 16 | `dos` → `memory` (6×): nu aplică regula „memory leak / crash fără corupere = dos” |
  | `gpt-5-mini` | 9 | `dos` → `memory` (3×) |

  Prima confuzie se poate repara cu exemple few-shot. A doua e o convenție a ghidului nostru, deci trebuie scrisă mai explicit în prompt.
- **Recomandare de cost:** pentru cele 7.521 de CVE-uri fără CWE, baseline-ul costă ~0 și rulează instant. `gpt-5-mini` ar costa ~$3,5 și ~5 ore secvențial (sau minute în paralel), pentru ~5 puncte în plus. La acest volum, merită LLM-ul de raționament. La volume de milioane, baseline-ul plus LLM doar pentru cazurile nesigure ar fi alegerea corectă.

## 2b. Sumarizare

**Set:** 15 CVE-uri din CISA KEV, alese aleator cu seed fix. **Metrica:** același judge, cu aceeași rubrică. Dovada e înregistrarea CVE-ului.

| | grounded | complete | useful | pass | cost / rezumat | sec / rezumat |
|---|---|---|---|---|---|---|
| `summarize` (`gpt-4.1-mini`) | 4,87 | 4,73 | 4,33 | 100% | $0,001 | 2,4 |

Feedback-ul judge-ului a fost citit pentru toate cele 15 rezumate:

- **Ancorare:** 14 din 15 au nota 5. Singura excepție (CVE-2025-15556, nota 4) recomandă dezactivarea unui updater, lucru pe care dovezile nu îl spun explicit.
- **Nota mai mică la *useful*** are o cauză repetată: rezumatul **nu menționează ID-ul CVE-ului și nici scorul sau vectorul CVSS**. Schema `Summary` nu are câmpuri pentru ele, pentru că în interfață ele apar oricum lângă rezumat. De 2 ori lipsește și versiunea reparată, deși era în dovezi.
- **Îmbunătățire (roadmap):** un antet **determinist** (ID, CVSS, KEV, EPSS) generat direct din înregistrare, fără LLM, și un câmp `fixed_versions` în schemă.

## 3. Agenți

**Set:** 12 întrebări scrise manual (`data/eval_questions.jsonl`) care acoperă toate tipurile: căutare după ID, extragere live din NVD (CVE-2021-44228), filtre, agregate globale, graf, prioritizare, comparație din mai multe părți și o întrebare **fără răspuns** (produs inexistent).

**Sisteme comparate:**

- *agent simplu*: `agent.run`;
- *orchestrator + judge*: `team.orchestrate`.

**Metrici:**

- **Judge LLM** (`gpt-5-mini`), cu notă de la 1 la 5 pentru *grounded*, *complete* și *useful*. Judge-ul vede dovezile, adică rezultatele uneltelor.
- **Pass:** toate notele ≥ 4 și niciun ID neancorat.
- **ID-uri neancorate**, verificare **deterministă**: ID-uri din răspuns care nu apar în nicio dovadă.
- **Expected-ID recall**: procentul de ID-uri așteptate (scrise manual) care apar în răspuns. E o verificare independentă de judge.
- **Cost (USD) și timp LLM** (suma latențelor apelurilor) per întrebare.

**Limitele LLM-as-a-judge** (Zheng et al., 2023): judge-ul poate prefera răspunsurile lungi sau un anumit stil și nu vede ce *nu* s-a căutat. De aceea:

- judge-ul e din altă familie decât generatorul;
- raportăm și două metrici deterministe (ID-uri neancorate, expected-ID recall);
- pentru varianta multi-agent, același judge decide și oprirea buclei. Scorul lui final e deci optimist. Comparația corectă e *nota primei ciorne* vs. *nota finală*.

### Rezultate (versiunea finală a codului)

| sistem | grounded | complete | useful | **pass** | ID-uri neancorate | expected-ID recall | cost / întrebare | timp LLM / întrebare |
|---|---|---|---|---|---|---|---|---|
| agent simplu | 4,83 | 4,67 | 4,50 | **10/12** | 0 | 0,944 | $0,002 | 5,4 s |
| orchestrator + judge | 4,75 | 4,42 | 4,33 | **11/12** | 0 | 0,958 | $0,014 | 55,9 s |

Varianta multi-agent are în medie 1,5 runde. Nota minimă a primei ciorne e 3,67, iar a răspunsului final e ≥ 4 în 11 din 12 cazuri.

### Interpretare

- **Multi-agentul câștigă o întrebare în plus (11 vs. 10), la un cost de 7 ori mai mare și un timp de 10 ori mai mare.** Câștigul vine din bucla Judge → revizie: prima ciornă are în medie nota minimă 3,67, iar revizia o urcă. Pentru un asistent interactiv, **agentul simplu e alegerea implicită** (5 secunde, $0,002). Varianta verificată e utilă pentru rapoarte, unde corectitudinea contează mai mult decât latența. Aceasta e recomandarea din *Building Effective Agents*: adaugi agenți doar când se măsoară un câștig.
- **Zero ID-uri inventate** în toate rulările. Verificarea deterministă n-a avut ce prinde aici, dar rămâne o plasă de siguranță ieftină.
- **Notele judge-ului variază între rulări.** Orice schimbare de prompt sau de descriere a unei unelte schimbă toate cererile, deci toate răspunsurile se regenerează. Între două rulări aproape identice, pass rate-ul orchestratorului a variat cu o întrebare. Cu n = 12, **o diferență de o întrebare (8 puncte procentuale) este zgomot.** Concluzia de mai sus se sprijină pe metricile robuste (cost, timp, expected-ID recall), nu pe 10 vs. 11.
- **Eșecuri rămase:**
  - *„SQL injection în pluginuri WordPress de rezervări din 2026-06”*: întrebarea cere exhaustivitate pe un subiect vag. Agentul vede doar top-k, iar judge-ul penalizează, corect, afirmațiile de completitudine pe care dovezile nu le susțin. Nici trei runde de revizie nu repară asta.
  - *Cisco ASA, agentul simplu*: lista e corectă (3/3), dar judge-ul cere precizări despre cât de complet e răspunsul.

### Istoria iterațiilor: ce a prins evaluarea

| versiune | schimbare | efect măsurat |
|---|---|---|
| v1 | – | La *„Câte CVE-uri Fortinet sunt în KEV? Dă-mi lista”*, **ambele sisteme au dat 8 din 14**. Judge-ul a **acceptat** răspunsul multi-agentului, pentru că se potrivea cu dovezile, iar dovezile erau incomplete. Doar metrica deterministă *expected-ID recall* a prins problema. |
| v2 | `cve_stats` listează toate ID-urile când sunt ≤ 30 | Niciun efect: agentul nu a apelat `cve_stats`. Trace-ul arată `search_cves(query="fortinet", kev_only=true)`, care întoarce top 8. |
| v3 | `search_cves` raportează câte CVE-uri trec de filtre și, dacă lista e trunchiată, indică explicit `cve_stats` | **14/14 la ambele sisteme.** A apărut însă o confuzie nouă: `cve_stats` afișa CVE-urile fără etichetă drept clasa `null`, iar agentul a raportat „null” drept cel mai frecvent tip. |
| v4 (final) | clasa `null` → `unlabeled (no CWE yet)` | Întrebarea despre kernelul Linux trece la ambele sisteme. |

**Lecția:** un LLM-judge vede doar ce i se arată. Nu poate detecta un răspuns incomplet dacă și dovezile sunt incomplete. De aceea evaluarea de agenți are nevoie de **răspunsuri așteptate scrise de om** (`expect`), nu doar de un judge. Iar reparația cea mai eficientă a fost în **ieșirea uneltei** („lista e trunchiată, folosește X”), nu în prompt.

## 4. Cost total

| ce | cost |
|---|---|
| embeddings pentru tot dataset-ul (o dată) | ~$0,30 |
| toate apelurile LLM ale proiectului: adnotare, date sintetice, 3 LLM-uri pe gold, rezumate, 4 rulări ale evaluării de agenți, teste manuale | **$0,76** (1.280 apeluri, ~0,96M tokeni de intrare) |
| o rulare completă `make eval` din cache | $0 |

Prețurile sunt cele din `cvescope/llm.py: PRICES` (USD per 1M tokeni). Costul real e afișat în bara laterală a aplicației și în `USAGE`.
