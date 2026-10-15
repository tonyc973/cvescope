# Ghid de adnotare: clasa vulnerabilității (`vuln_class`)

## Sarcina

Pentru fiecare CVE, alegem **o singură clasă** care descrie **cauza de bază** (slăbiciunea din cod), nu consecința.

> Exemplu: „CSRF în pluginul X permite includere de cod la distanță” → `csrf`, nu `code_injection`. Cauza e lipsa protecției CSRF; codul inclus e doar efectul.

## Clasele (taxonomia v1)

| clasă | ce înseamnă | CWE-uri mapate (`cvescope/dataset.py: TAXONOMY`) |
|---|---|---|
| `sqli` | injecție SQL / NoSQL | 89, 564, 943 |
| `xss` | cross-site scripting | 79, 80, 83, 87 |
| `csrf` | cross-site request forgery | 352 |
| `ssrf` | server-side request forgery | 918 |
| `deserialization` | deserializare de date nesigure | 502 |
| `path_file` | path traversal, symlink, upload nerestricționat, DLL / search-path hijacking | 22, 23, 24, 35, 36, 59, 61, 73, 427, 428, 434 |
| `code_injection` | injecție de comenzi OS / cod / template / argumente / **file inclusion** | 74, 75, 77, 78, 88, 91, 94, 95, 96, 98, 917, 1336 |
| `memory` | coruperea memoriei: overflow, out-of-bounds, use-after-free, NULL deref, integer overflow, type confusion | 119–131, 190, 191, 415, 416, 476, 680, 787, 788, 805, 823, 824, 843, 908, 909 |
| `access_control` | autentificare / autorizare lipsă sau greșită, escaladare de privilegii, IDOR, credențiale hard-coded, permisiuni | 250, 266, 269, 276, 284–290, 294, 306, 307, 425, 521, 522, 639, 640, 732, 798, 862, 863, 1390, 1391 |
| `info_leak` | expunere de informații sensibile | 200, 201, 203, 209, 212, 215, 312, 319, 359, 497, 532, 538, 552 |
| `dos` | epuizarea resurselor, buclă infinită, ReDoS, **memory leak**, crash fără corupere de memorie | 400, 401, 404, 674, 703, 754, 755, 770, 772, 789, 834, 835, 1333 |
| `other` | orice altceva: race condition, criptografie / certificate, validare generică (CWE-20), open redirect, UI misrepresentation | restul |

## Reguli

1. **Cauză, nu consecință.** RCE, „data leak” sau „privilege escalation” sunt de obicei consecințe. Căutați *mecanismul*.
2. **Cel mai specific câștigă.** Dacă un CVE are mai multe CWE-uri, se alege prima clasă în ordinea din tabel. Astfel `sqli` bate `code_injection` (CWE-74 e părintele generic al injecțiilor).
3. **Memory leak = `dos`**, nu `memory`. `memory` e rezervat coruperii memoriei.
4. **File inclusion (CWE-98) = `code_injection`**, nu `path_file`. Atacatorul controlează ce cod se execută.
5. **Upload nerestricționat (CWE-434) = `path_file`**, chiar dacă duce la execuție de cod.
6. **Lanțuri de vulnerabilități:** alegeți punctul de intrare, adică prima slăbiciune exploatată.
7. **Dacă descrierea contrazice CWE-ul atribuit de CNA, descrierea câștigă**, iar cazul se notează ca eroare a etichetei NVD.

## Procesul (`python -m cvescope.annotate`)

1. **Eșantion:** 12 CVE-uri per clasă × 12 clase = **144**, stratificat. Toate provin din partea de **test** a separării pe grupuri, deci baseline-ul nu le-a văzut la antrenare, și sunt câte un reprezentant per cluster de aproape-duplicate.
2. **Adnotatorul A:** maparea CWE → clasă. CWE-urile vin de la analiștii NVD sau CNA, deci sunt etichete umane indirecte.
3. **Adnotatorul B:** LLM (`gpt-4.1-mini`), zero-shot, cu ieșire structurată (`rationale`, apoi `vuln_class`).
4. **Acord:** acord brut și κ Cohen.
5. **Arbitraj:** unde A ≠ B, se completează `gold_class` și `adjudication_note` după regulile de mai sus. Unde A = B, `gold_class` se precompletează.
6. Fișierul `data/gold/gold.csv` **nu este suprascris niciodată** de script, ca munca de arbitraj să nu se piardă.

> **Transparență:** cele 24 de dezacorduri au fost arbitrate cu asistență AI (Claude), aplicând regulile de mai sus. Fiecare decizie are motivul scris în `adjudication_note`. Înainte de prezentarea 2, un membru al echipei trebuie să verifice aceste 24 de rânduri.

## Rezultate

| metrică | valoare |
|---|---|
| CVE-uri adnotate | 144 |
| Acord brut A vs. B | 83,3% |
| κ Cohen A vs. B | **0,818** (acord „aproape perfect” pe scala Landis & Koch) |
| Eticheta NVD/CNA corectă față de gold | **95,1%** |
| LLM (`gpt-4.1-mini`) corect față de gold | 87,5% |

**Ce am învățat din arbitraj:**

- **Erorile LLM-ului sunt sistematice:** etichetează **consecința** (RCE → `code_injection`, acces neautorizat → `access_control`) în loc de cauză. Prompt-ul cere explicit cauza, iar eroarea persistă. Pentru v2 a promptului: exemple few-shot cu exact aceste capcane.
- **Erorile etichetei NVD vin din două surse:**
  - **goluri în taxonomia v1**: CWE-369 (împărțire la zero) → `dos`; 407 (complexitate algoritmică) → `dos`; 457 (memorie neinițializată) → `memory`; 602 (client-side enforcement) → `access_control`; 822 (untrusted pointer dereference) → `memory`;
  - **CWE-uri CNA care descriu consecința**: CVE-2026-57909 e descris ca path traversal, dar are CWE-94.
- **Limita etichetei unice:** CVE-2026-75754 are un lanț de 3 CWE-uri (autentificare lipsă + SSRF + credențiale hard-coded). O etichetă multi-label ar fi mai corectă (vezi [roadmap](roadmap.md)).

**Taxonomia v2 (de făcut):** adăugăm cele 5 CWE-uri de mai sus, apoi reconstruim dataset-ul și recalculăm acordul. Setul gold rămâne valabil, pentru că e indexat după ID.
