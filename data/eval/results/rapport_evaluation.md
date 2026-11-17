# Rapport d'évaluation

Généré le 2026-11-17 22:39 UTC à partir de `data/eval/results`.

| Réglage | Valeur |
|---|---|
| ollama_model | `mistral` |
| embed_model | `sentence-transformers/all-MiniLM-L6-v2` |
| top_k | `5` |
| hybrid_alpha | `0.6` |
| temperature | `0.0` |
| seed | `42` |
| corpus | `100 documents, 406 chunks` |
| index_created_at | `2026-11-17T22:14:30+00:00` |

## Résultats globaux

| Métrique | RAG hybride | RAG FAISS | LLM seul |
|---|---|---|---|
| Couverture des éléments attendus | 0,975 | 0,975 | 0,375 |
| Éléments absents de la question retrouvés | 24/25 | 24/25 | 0/25 |
| Rappel du contexte | 1,000 | 1,000 | – |
| Précision du contexte | 0,960 | 0,960 | – |
| Fidélité au contexte | 1,000 | 1,000 | – |
| Taux d'hallucination : réponse fausse ou incomplète, sans réserve | 0,050 | 0,050 | 0,500 |
| Abstentions : réponse incomplète signalée | 0,000 | 0,000 | 0,500 |
| Réponses citant un fait vérifiable inventé | 0,000 | 0,000 | 0,000 |
| Latence moyenne (s) | 33,302 | 15,870 | 13,514 |

## Couverture par catégorie

| Catégorie | RAG hybride | RAG FAISS | LLM seul |
|---|---|---|---|
| cve | 1,000 | 1,000 | 0,250 |
| mitre | 0,950 | 0,950 | 0,500 |

## Détail par question

Couverture et mode de recherche ; ⚠ : réponse fausse ou incomplète donnée sans réserve (avec les faits inventés éventuels) ; ∅ : abstention.

| Question | RAG hybride | RAG FAISS | LLM seul |
|---|---|---|---|
| q01 : What is T1053 in MITRE ATT&CK? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ⚠ |
| q02 : What is T1053.005 in MITRE ATT&CK? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ⚠ |
| q03 : What is T1021.005 in MITRE ATT&CK? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ⚠ |
| q04 : What is T1560.001 in MITRE ATT&CK? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ⚠ |
| q05 : What is T1055.011 in MITRE ATT&CK? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ⚠ |
| q06 : What is T1205.002 in MITRE ATT&CK? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ⚠ |
| q07 : What is T1053.002 in MITRE ATT&CK? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ⚠ |
| q08 : What is T1053.003 in MITRE ATT&CK? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ⚠ |
| q09 : What is T1053.007 in MITRE ATT&CK? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ⚠ |
| q10 : What is the MITRE ATT&CK ID for Scheduled Task? | 0,500 (hybrid) ⚠ | 0,500 (faiss) ⚠ | 0,500 (llm_only) ⚠ |
| q11 : What is CVE-2024-13785? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ∅ |
| q12 : What is the severity and weakness of CVE-2024-13785? | 1,000 (exact) | 1,000 (exact) | 0,000 (llm_only) ∅ |
| q13 : What is CVE-2025-13910? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ∅ |
| q14 : What is the severity and weakness of CVE-2025-13910? | 1,000 (exact) | 1,000 (exact) | 0,000 (llm_only) ∅ |
| q15 : What is CVE-2025-14037? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ∅ |
| q16 : What is the severity and weakness of CVE-2025-14037? | 1,000 (exact) | 1,000 (exact) | 0,000 (llm_only) ∅ |
| q17 : What is CVE-2026-0609? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ∅ |
| q18 : What is the severity and weakness of CVE-2026-0609? | 1,000 (exact) | 1,000 (exact) | 0,000 (llm_only) ∅ |
| q19 : What is CVE-2026-1093? | 1,000 (exact) | 1,000 (exact) | 0,500 (llm_only) ∅ |
| q20 : What is the severity and weakness of CVE-2026-1093? | 1,000 (exact) | 1,000 (exact) | 0,000 (llm_only) ∅ |

## Définitions

- **Couverture** : part des éléments attendus (ID, nom officiel, produit, sévérité, CWE) présents dans la réponse, en mot entier et sans tenir compte de la casse ; une sévérité attendue en anglais est aussi acceptée en français.
- **Rappel du contexte** : part des éléments attendus présents dans les extraits transmis au LLM.
- **Précision du contexte** : part des extraits transmis qui proviennent du ou des documents de référence de la question.
- **Fidélité** : part des faits vérifiables de la réponse (identifiants CVE, ATT&CK, CWE, DET, M ; scores CVSS ; sévérités) présents dans la question ou les extraits transmis. Moyenne sur les réponses qui citent au moins un fait.
- **Taux d'hallucination** : part des réponses qui manquent un élément attendu absent de la question sans le signaler, ou qui citent un fait vérifiable inventé. Une réponse qui donne un mauvais nom de technique compte ici.
- **Abstentions** : part des réponses incomplètes qui disent ne pas pouvoir répondre.
- **Faits inventés** : part des réponses citant un fait vérifiable absent de la question, des extraits transmis et des documents de référence de la base.

Ces métriques sont des approximations par entités de celles de RAGAS : elles ne jugent pas les paraphrases.
