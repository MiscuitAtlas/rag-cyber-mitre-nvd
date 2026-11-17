# Résultats de la version 1 (archive)

Résultats obtenus avec la première version du projet (scripts `src/`, remplacés par le paquet `rag_cyber`), sur le
corpus complet de l'époque : 691 techniques ATT&CK et 1 948 CVE, soit 2 639 documents et 3 926 chunks.

- Recherche : correspondance exacte sur le premier identifiant de la question, sinon FAISS seul (top 5).
- Génération : Mistral via Ollama, sans température ni graine fixées.
- Métrique : couverture des éléments attendus, par comparaison de sous-chaînes.

| Fichier | Contenu |
|---|---|
| `rag_results.json` | Réponses du RAG, mode de recherche et identifiants des chunks utilisés |
| `llm_only_results.json` | Réponses de Mistral sans contexte |
| `comparison_results.json`, `comparison_summary.txt` | Comparaison question par question et moyennes |

Couverture moyenne : RAG 0,85, LLM seul 0,40. Relue avec la correspondance en mot entier de la version 2
(`rag_cyber/evaluation.py`), elle donne RAG 0,85 et LLM seul 0,375 : pour `T1053.002`, l'élément attendu « At »
n'était trouvé dans la réponse du LLM seul que dans « ATT&CK » et « catalogue ». Ce recalcul est vérifié par
`tests/test_evaluation.py`.

Ces fichiers ne contiennent pas le texte des extraits transmis au LLM : les métriques de contexte et de fidélité de la
version 2 ne peuvent pas leur être appliquées. Elles s'obtiennent en relançant `python -m rag_cyber evaluate`.
