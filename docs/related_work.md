# Studiul literaturii de specialitate

Pe scurt: ce s-a mai făcut, ce preluăm și prin ce diferă CVEScope.

## A. Vulnerabilități și NLP

| lucrare | ce face | ce preluăm / diferența |
|---|---|---|
| **Das et al.**, *V2W-BERT: A Framework for Effective Hierarchical Multiclass Classification of Software Vulnerabilities*, IEEE DSAA 2021 ([arXiv 2102.11498](https://arxiv.org/abs/2102.11498)) | Mapează CVE → CWE cu un Transformer + link prediction. Raportează până la 97% acuratețe pe separare aleatoare și 94% pe separare temporală. | Arată că **modul de separare contează**. Noi facem separare pe clustere de aproape-duplicate și raportăm efectul. Folosim 12 clase grosiere, nu sute de CWE-uri. |
| **Shahid & Debar**, *CVSS-BERT: Explainable NLP to Determine the Severity of a Computer Security Vulnerability from its Description*, ICMLA 2021 ([arXiv 2111.08510](https://arxiv.org/abs/2111.08510)) | Câte un clasificator BERT per metrică CVSS, prezise din descriere, plus explicabilitate prin saliency. | Sarcina de **severitate din text**. Noi folosim un baseline TF-IDF și raportăm cât de greu e să prezici severitatea doar din descriere. |
| **Alam et al.**, *CTIBench: A Benchmark for Evaluating LLMs in Cyber Threat Intelligence*, NeurIPS 2024 Datasets & Benchmarks | Benchmark pentru LLM-uri pe sarcini CTI, inclusiv **CTI-RCM** (CVE → CWE) și **CTI-VSP** (prezicerea vectorului CVSS). | Formularea zero-shot „analizează descrierea și mapează la CWE, cu justificare”. Noi comparăm mai multe LLM-uri cu un baseline clasic, pe un set gold arbitrat. |
| **Le, Chen & Babar**, *A Survey on Data-driven Software Vulnerability Assessment and Prioritization*, ACM Computing Surveys ([arXiv 2107.08364](https://arxiv.org/abs/2107.08364)) | Taxonomia metodelor ML/DL/NLP pentru evaluarea și prioritizarea vulnerabilităților. | Cadrul general. Problemele semnalate acolo (etichete zgomotoase, separare temporală, dezechilibru) sunt cele pe care le tratăm explicit. |
| **Jacobs et al.**, *Exploit Prediction Scoring System (EPSS)*, Digital Threats: Research and Practice, 2021 ([arXiv 1908.04856](https://arxiv.org/abs/1908.04856)) | Model deschis care estimează probabilitatea de exploatare a unui CVE. | Folosim scorurile EPSS ca semnal de prioritizare: KEV > EPSS > CVSS. |

## B. Regăsire, RAG și agenți

| lucrare | folosită în |
|---|---|
| **Robertson & Zaragoza**, *The Probabilistic Relevance Framework: BM25 and Beyond*, Foundations and Trends in IR, 2009 | BM25 implementat de noi (`search.py`) |
| **Cormack, Clarke & Büttcher**, *Reciprocal Rank Fusion outperforms Condorcet and individual Rank Learning Methods*, SIGIR 2009 | fuziunea BM25 + dense, k = 60 |
| **Lewis et al.**, *Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks*, NeurIPS 2020 | arhitectura RAG |
| **Edge et al.**, *From Local to Global: A Graph RAG Approach to Query-Focused Summarization*, arXiv 2024 | ideea că întrebările *globale* cer agregare peste toată colecția → `cve_stats` și graful |
| **Yao et al.**, *ReAct: Synergizing Reasoning and Acting in Language Models*, ICLR 2023 | bucla agentului |
| **Madaan et al.**, *Self-Refine: Iterative Refinement with Self-Feedback*, NeurIPS 2023 | bucla Judge → revizie |
| **Zheng et al.**, *Judging LLM-as-a-Judge with MT-Bench and Chatbot Arena*, NeurIPS 2023 | limitele judge-ului: preferința pentru propriul stil, poziția, lungimea → judge din altă familie de modele + verificări deterministe |
| **Anthropic**, *Building Effective Agents*, 2024 | orchestrator–workers și evaluator–optimizer; „începe simplu, adaugă agenți doar când se măsoară un câștig” |

## C. Date și metodologie

| lucrare | folosită în |
|---|---|
| **Broder**, *On the Resemblance and Containment of Documents*, 1997; **Leskovec, Rajaraman & Ullman**, *Mining of Massive Datasets*, cap. 3 | MinHash + LSH pentru aproape-duplicate |
| **Gebru et al.**, *Datasheets for Datasets*, Communications of the ACM, 2021 | [dataset_card.md](dataset_card.md) |
| **Kapoor & Narayanan**, *Leakage and the Reproducibility Crisis in Machine-Learning-Based Science*, Patterns, 2023 | separarea pe grupuri împotriva scurgerilor între train și test |
| **Cormen et al.**, *Introduction to Algorithms*, ed. 4 | union-find, selecție în O(n), memoizare |

## Ce aduce CVEScope în plus

1. Un dataset **actual** (până la 15.10.2026) care unește NVD, KEV, EPSS și CWE, cu **clustere de aproape-duplicate** și un **set gold arbitrat**, în care am măsurat calitatea etichetelor NVD (95,1%).
2. O comparație cinstită, pe același set gold, între un clasificator clasic, mai multe LLM-uri și eticheta oficială, cu **cost și latență**.
3. Un asistent agentic cu **verificare deterministă a ancorării** și o comparație cu varianta multi-agent (calitate vs. cost).
