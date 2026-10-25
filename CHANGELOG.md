# Changelog

Toutes les évolutions notables de **khaleesi** sont documentées dans ce fichier.
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et
[SemVer](https://semver.org/lang/fr/).

## [2.1.0] — 2026-10-25

### Corrigé
- **429 traités comme des erreurs réseau génériques** : une réponse 429
  n'incrémente plus le compteur d'erreurs consécutives ; elle est comptée
  séparément (`rate_limit_hits`) et dispose de sa propre gestion
  (`--stop-on-429` / backoff adaptatif).
- **Candidats perdus sur 429** : en mode `--adaptive`, un candidat ayant reçu un
  429 est re-mis en file au lieu d'être abandonné (un vrai mot de passe pouvait
  être manqué lors du premier passage).
- **`--delay 0` neutralisait le backoff adaptatif** : le facteur multiplicatif
  tombait sur 0×factor = 0 ; un plancher de 0,25 s garantit une décroissance
  exploitable.
- **Mode enum inopérant** : `build_request()` ignorait l'identifiant de sonde et
  envoyait toujours `--email` — toutes les sondes (valides et inexistantes)
  mesuraient le même temps de réponse. Le paramètre est désormais transmis
  (`identifier`), le mode enum détecte correctement les écarts de timing.
- **Extraction de token** : un corps de réponse en JSON invalide avec
  `--token-json-path` retournait `None` au lieu de retomber sur la regex.

### Ajouté
- **Dictionnaire streamé** : lecture en générateur (une passe de comptage +
  lecture ligne à ligne) — rockyou.txt et dictionnaires de plusieurs Go
  fonctionnent sans saturation mémoire ; `--dedup` optionnel.
- **`--stop-on-429 N`** : arrêt immédiat et distinct après N réponses 429.
- **`--adaptive`** : backoff adaptatif exponentiel sur 429 (facteur
  `--backoff-factor`, défaut 1.5 ; plafond `--max-delay`, défaut 30 s ;
  plancher 0,25 s ; décroissance progressive entre 429) pour cartographier le
  seuil réel de rate-limiting au lieu d'abandonner.
- **Rotation de proxies** : `--proxy-list` (un proxy par thread, round-robin),
  en plus du `--proxy` unique.
- **Flows multi-étapes CSRF** : `--pre-request-url` (GET préalable par
  tentative), extraction par `--token-regex` ou `--token-json-path`, injection
  via `--token-field` ou `--token-header`, cookies de session persistants.
- **Règles de mutation** (`--rules`) : sous-ensemble Hashcat —
  `:` `l` `u` `c` `r` `d` `$X` `^X` `sXY` `TN`.
- **Mode énumération de comptes** (`--mode enum`, `--enum-probes`,
  `--enum-threshold-ms`, `--enum-fake-domain`) : timing d'un identifiant valide
  connu vs identifiants inexistants, statistiques moyenne/médiane/écart-type/
  min/max, exclusion des sondes 429/5xx des statistiques de timing.
- **Export CSV** (`--csv`) : résumé à plat (brute) ou une ligne par sonde (enum).
- **Rapport JSON enrichi** : mappage OWASP (OAT-007, WSTG-ATHN-03, WSTG-IDNT-04),
  `stopped_reason`, `rate_limit_hits`, `proxies_used`, `adaptive_backoff`.
- **Tests unitaires** : `tests/test_is_success.py`, `tests/test_rules.py`,
  `tests/test_token.py` (44 tests) — `python3 -m pytest tests/ -q`.

### Documentation
- README : badge v2.1.0, sections « Obtenir un dictionnaire » (miroirs rockyou +
  avertissement d'intégrité SHA256), « Format du rapport » (schéma JSON + CSV),
  exemples pour chaque nouvelle option, section « À propos ».

## [2.0.0] — version initiale documentée

- Brute force HTTP multithread (ThreadPoolExecutor), mode interactif ou CLI.
- Détection de succès flexible : `--success-key`, `--fail-key`,
  `--success-status`, `--success-text`, `--body-template`.
- Détection de rate-limiting (avertissement 429/503), `--stop-on-errors`.
- Proxy unique (`--proxy`), en-têtes personnalisés, User-Agent, `--insecure`.
- Reprise `--start-line`, échantillonnage `--max-attempts`.
- Rapport JSON (`-o`), codes de retour standardisés (0/1/2/3/130).
