# Fișa dataset-ului CVEScope (datasheet)

Structura urmează *Datasheets for Datasets* (Gebru et al., CACM 2021). Cifrele vin din `python -m cvescope.dataset --stats`.

## 1. Motivație

**De ce există.** NVD publică acum peste 70.000 de CVE-uri pe an (2026 avea deja 74.332 pe 15 octombrie). O echipă de securitate nu le poate citi pe toate. Are nevoie să **găsească** rapid ce o privește, să **înțeleagă** fiecare vulnerabilitate și să **prioritizeze** ce repară mai întâi. Multe CVE-uri noi nu au încă un CWE sau un scor CVSS de la NVD, din cauza backlog-ului, deci o **clasificare automată** din descriere are valoare practică.

**Cine l-a creat.** Echipa proiectului CVEScope, la disciplina *Ingineria algoritmilor pentru sisteme AI* (Master Inginerie Software, FMI, Universitatea din București, 2026–2027).

## 2. Compoziție

| | |
|---|---|
| Instanțe | **116.902** CVE-uri (CVE-2025-\*: 43.577 · CVE-2026-\*: 73.325), fără cele respinse (REJECTED) |
| Fișier | `data/cves.jsonl.gz` (24 MB), o înregistrare JSON pe linie |
| Snapshot | feed-uri NVD 2.0 din 2026-10-15T03:00Z · catalog CISA KEV 2026.10.15 · EPSS model v2026.06.15, scoruri din 2026-10-15 · CWE v4.20 |

**Câmpurile unei înregistrări:**

| câmp | sursă | descriere |
|---|---|---|
| `id`, `published`, `status` | NVD | `status` ∈ Analyzed, Deferred, Modified, Awaiting Analysis, Received, Undergoing Analysis |
| `description` | NVD (en) | 51 de cuvinte la mediană, 115 la p90, maximum 683 |
| `cwes` | NVD + CNA | lista de CWE-uri (`NVD-CWE-noinfo`/`Other` sunt eliminate) |
| `vuln_class` | **derivat** | una din cele 12 clase ([ghid](annotation_guidelines.md)); `null` dacă nu există CWE |
| `cvss` | NVD + CNA | `{version, score, severity, vector}`; preferă v3.1 > v4.0 > v3.0 > v2 și scorul NVD (Primary) celui al CNA |
| `products` | NVD CPE + CVE 5 `affected` | `vendor:produs`, normalizat la `[a-z0-9_]`, maximum 50 |
| `references` | NVD | maximum 15 URL-uri |
| `kev` | CISA KEV | `{date_added, name, ransomware, action}` dacă vulnerabilitatea e **exploatată activ** |
| `epss`, `epss_pct` | FIRST EPSS | probabilitatea de exploatare în următoarele 30 de zile și percentila |
| `cluster` | **derivat** | ID-ul reprezentantului clusterului de aproape-duplicate (MinHash, Jaccard ≥ 0,8) |

**Distribuții:**

- Status: Analyzed 50.800 · Deferred 43.979 · Modified 8.782 · Awaiting Analysis 6.911 · Received 5.191 · Undergoing Analysis 1.239.
- Cu etichetă de clasă (are CWE): **109.381 (93,6%)**; cu CVSS: 113.961 (97,5%); cu EPSS: 100%.
- În CISA KEV: **364**; EPSS ≥ 0,1: 787. Distribuția e extrem de dezechilibrată: aproape toate CVE-urile au risc mic de exploatare.
- `vuln_class`: access_control 22.995 · memory 18.846 · other 16.509 · xss 14.051 · *fără etichetă* 7.521 · code_injection 7.377 · sqli 7.153 · path_file 6.735 · dos 4.863 · info_leak 4.105 · csrf 2.598 · ssrf 2.408 · deserialization 1.741.
- Severitate: MEDIUM 47.921 · HIGH 46.922 · CRITICAL 15.322 · LOW 3.761 · fără 2.941.
- Vendori de top (după numărul de CVE-uri): linux, microsoft, google, oracle, red_hat, adobe, ibm, apple, siemens, apache.

**Aproape-duplicate.** 14,3% din înregistrări (16.696) au cel puțin o „geamănă” cu Jaccard ≥ 0,8 pe 3-grame de cuvinte. Avem 104.627 de clustere, iar cel mai mare are 394 de membri. Sunt mai ales descrieri generate din șablon, de tipul *„The X plugin for WordPress is vulnerable to Stored Cross-Site Scripting via…”*. Nu le ștergem, pentru că sunt CVE-uri reale și distincte, dar le folosim la:

- separarea train/test pe grupuri, ca să nu existe scurgeri între cele două părți ([metodologie](methodology.md#4-clasificare));
- eșantionarea setului gold și a întrebărilor sintetice: un singur reprezentant per cluster, ca ținta să fie neambiguă.

**Fișiere derivate (versionate în repo):**

- `data/gold/gold.csv`: 144 de CVE-uri adnotate dublu și arbitrate.
- `data/synth/questions.jsonl`: întrebări sintetice pentru evaluarea căutării.
- `data/eval_questions.jsonl`: 12 întrebări scrise manual pentru agenți.
- `data/cwe_names.json`: dicționarul de nume CWE.

## 3. Colectare

`python -m cvescope.dataset` descarcă fișiere publice (fără autentificare):

| sursă | URL | ce aduce |
|---|---|---|
| NVD JSON 2.0 feeds | `nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{an}.json.gz` | CVE-urile, CWE, CVSS, CPE |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | exploatare confirmată |
| FIRST EPSS | `epss.empiricalsecurity.com/epss_scores-current.csv.gz` | probabilitate de exploatare |
| MITRE CWE | `cwe.mitre.org/data/xml/cwec_latest.xml.zip` | numele slăbiciunilor |

Am folosit feed-urile anuale și nu API-ul REST, pentru că API-ul fără cheie e limitat la 5 cereri pe 30 de secunde: 117.000 de înregistrări ar fi durat câteva ore, față de un minut cu feed-urile. API-ul REST (`services.nvd.nist.gov/rest/json/cves/2.0`) e folosit **live** de agent, pentru CVE-uri din alți ani, cu același parser (`parse_nvd`).

## 4. Preprocesare

1. Eliminăm CVE-urile `Rejected` și pe cele fără descriere în engleză.
2. Normalizăm (`parse_nvd`): CWE-uri unice și sortate; un singur CVSS, după regula de prioritate de mai sus; produse `vendor:produs` din CPE și din blocul `affected`. Placeholder-ele `n/a` și `unknown` ca produs sunt eliminate, altfel ar fi legat mii de CVE-uri în graf.
3. Etichetăm `vuln_class` din CWE (taxonomia v1, [ghid](annotation_guidelines.md)).
4. Îmbogățim cu KEV și EPSS, prin join pe ID.
5. Deduplicăm cu MinHash (128 de permutări) + LSH (16 benzi × 8 rânduri) + componente conexe în graful perechilor similare. Rezultatul e câmpul `cluster`.

Totul e determinist (seed fix); `make data` reproduce fișierul în aproximativ un minut.

## 5. Utilizări

- **Prevăzute:** căutare de vulnerabilități, asistent de triaj, clasificarea tipului de vulnerabilitate și a severității din text, cercetare în RAG/agenți.
- **Nepotrivite:** decizii de securitate automate fără verificare umană. Datele sunt un snapshot și se învechesc în câteva zile. EPSS și KEV se schimbă zilnic.

## 6. Limitări și bias

- **Acoperire temporală:** doar CVE-2025/2026. Agentul aduce live alți ani, dar căutarea semantică nu îi acoperă.
- **Etichete zgomotoase:** CWE-urile atribuite de CNA sunt uneori greșite sau prea generice. Pe setul gold, eticheta derivată din NVD/CNA e corectă în **95,1%** din cazuri ([ghid](annotation_guidelines.md#rezultate)).
- **Taxonomia v1 are goluri**, descoperite la arbitraj: CWE-369, 407, 457, 602 și 822 cad greșit în `other`.
- **Dezechilibru:** `deserialization` (1.741) e de 13 ori mai rară decât `access_control`. Raportăm macro-F1, nu doar acuratețea.
- **Normalizarea produselor e imperfectă:** `oracle` și `oracle_corporation`, sau `apache` și `apache_software_foundation`, apar ca noduri diferite.
- **Bias de sursă:** CNA-urile mari (Wordfence, Patchstack, VulDB) produc descrieri șablon, iar ecosistemul WordPress e supra-reprezentat.

## 7. Licențe și atribuire

- **NVD:** date publice ale guvernului SUA. *This product uses data from the NVD API but is not endorsed or certified by the NVD.*
- **CISA KEV:** CC0 1.0.
- **EPSS:** © FIRST, utilizare liberă cu atribuire. Jacobs et al., *Exploit Prediction Scoring System (EPSS)*, 2021.
- **CWE™:** © MITRE Corporation, conform termenilor de utilizare CWE.
- Câmpurile derivate (`vuln_class`, `cluster`, setul gold, întrebările sintetice) sunt publicate sub licența MIT a repository-ului.

## 8. Mentenanță

Reconstruire: `make data index` (cu feed-uri proaspete, ștergeți întâi `data/raw/`). Pentru alți ani: `python -m cvescope.dataset --years 2024 2025 2026`.
