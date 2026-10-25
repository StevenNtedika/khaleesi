# Khaleesi 🔥 — mère des dragons

![Version](https://img.shields.io/badge/version-2.1.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Licence](https://img.shields.io/badge/licence-MIT-green)
![Plateforme](https://img.shields.io/badge/plateforme-Linux%20%7C%20macOS-lightgrey)
![Usage](https://img.shields.io/badge/usage-tests%20autorisés%20uniquement-red)

Outil de **test de résistance des identifiants** (brute force) et de
**détection d'énumération de comptes** sur un endpoint d'authentification
HTTP, destiné aux tests d'intrusion **autorisés**.

> *« Chaque thread est un dragon. Quand un mot de passe faible se présente : Dracarys. »*

![Démo de Khaleesi](demo.gif)

> ⚠️ **Avertissement légal** : à utiliser uniquement sur votre propre
> infrastructure ou avec un mandat écrit du propriétaire du système.
> Toute utilisation non autorisée est illégale.

## Fonctionnalités

### Moteur de brute force
- Mode **interactif** (l'URL, l'identifiant et le dictionnaire sont demandés) ou **100 % CLI**
- **Multithreading** configurable (`-t`) avec débit affiché (req/s)
- **Dictionnaire streamé** : le fichier est lu ligne par ligne via un générateur —
  rockyou.txt (14 M lignes) comme crackstation.txt (15 Go) passent sans saturer la RAM
- Déduplication optionnelle en mémoire (`--dedup`)
- Détection de succès configurable : clé JSON (`--success-key` / `--fail-key`),
  code HTTP (`--success-status`) ou texte (`--success-text`)
- Corps de requête personnalisé (`--body-template`, `--field-email`, `--field-password`) : JSON, formulaires, etc.

### Résistance au rate-limiting
- `--stop-on-429 N` : arrêt **immédiat** après N réponses 429, distinct du compteur
  d'erreurs réseau consécutives (`--stop-on-errors`)
- `--adaptive` : backoff adaptatif — à chaque 429, le délai entre requêtes est
  multiplié par le facteur (`--backoff-factor`, défaut 1.5, plancher 0.25 s,
  plafond `--max-delay`) puis décroît progressivement. Les candidats reçus en 429
  sont **re-mis en file** au lieu d'être perdus : cartographie du seuil réel de
  rate-limiting sans abandonner de mot de passe.
- Reprise et échantillonnage : `--start-line`, `--max-attempts`

### Flows d'authentification multi-étapes
- `--pre-request-url` : GET préalable avant chaque tentative (token CSRF frais +
  cookies de session persistants)
- Extraction du token par regex (`--token-regex`) ou JSONPath (`--token-json-path`),
  injection en champ de payload (`--token-field`) ou en en-tête (`--token-header`)

### Mutations et egress
- Règles de mutation façon Hashcat (`--rules`) : combiner une petite wordlist avec
  des variantes (`password` → `Password1!`, `p@ssword`, …) sans dictionnaire de 14 M lignes
- Rotation de proxies (`--proxy-list`) : un proxy par thread, round-robin ;
  proxy unique via `--proxy` ; en-têtes personnalisés, User-Agent, `--insecure`

### Mode énumération de comptes (`--mode enum`)
Mesure et compare le temps de réponse d'un identifiant **valide connu** contre des
identifiants **inexistants** pour détecter les timing attacks sur l'endpoint
(WSTG-IDNT-04). Statistiques moyenne/médiane/écart-type/min/max par classe,
exclusion automatique des sondes 429/5xx (bruit transitoire), seuil configurable.

### Sorties
- **Rapport JSON** (`-o`) : voir « Format du rapport » ci-dessous
- **Export CSV** (`--csv`) : résumé (mode brute) ou une ligne par sonde (mode enum),
  compatible tableur / rapport de pentest
- Codes de retour propres pour l'automatisation

## Démo (texte)

```text
╔══════════════════════════════════════════════╗
║      khaleesi v2.1.0 — mère des dragons      ║
╚══════════════════════════════════════════════╝

[INFO] Dico    : wordlist.txt (100 candidats, démarrage ligne 1)
[INFO] Config  : 5 thread(s), timeout 10.0s, délai 0.0s
[WARN] 429 reçu — backoff adaptatif : délai porté à 0.38s.
[INFO] Terminé en 6.04s — 20 requêtes (3.3 req/s), 3 erreur(s), 3 x 429.
[OK  ] SUCÈS : mot de passe trouvé 'Dracarys!' (ligne 7, statut HTTP 200, 6.04s)
```

## Installation

```bash
pip install -r requirements.txt
```

Python ≥ 3.10, `requests` (seule dépendance).

## Obtenir un dictionnaire

Linux (Kali/Parrot) : généralement préinstallé dans
`/usr/share/wordlists/rockyou.txt.gz` (décompresser avec `gunzip`).

Windows / autres environnements :
- SecLists (copie vérifiée) : <https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/rockyou.txt.tar.gz>
- Miroir original : <https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt>

> ⚠️ **Intégrité** : rockyou.txt circule sur plusieurs miroirs non officiels.
> Vérifiez le SHA256 du fichier téléchargé avant utilisation et comparez-le à
> une source de confiance (par ex. la somme publiée dans les release notes de
> SecLists). Ne faites jamais confiance à un dictionnaire téléchargé sans
> vérification — un dictionnaire piégé est un vecteur d'attaque classique.

```bash
# exemple de vérification
sha256sum rockyou.txt
```

## Utilisation

Mode interactif :

```bash
python3 khaleesi.py
```

Mode CLI :

```bash
python3 khaleesi.py \
    -u http://localhost:3000/api/auth/login \
    -e cible@exemple.com \
    -w /usr/share/wordlists/rockyou.txt \
    -t 10 --delay 0.1 -o rapport.json
```

Exemples de détection personnalisée :

```bash
# Clé JSON de succès différente
python3 khaleesi.py -u ... -e ... -w ... --success-key authenticated

# Succès basé sur le code HTTP
python3 khaleesi.py -u ... -e ... -w ... --success-status 200

# Formulaire classique
python3 khaleesi.py -u ... -e ... -w ... \
    --body-template 'login={EMAIL}&pass={PASSWORD}' --success-text 'Bienvenue'
```

Flow avec CSRF token récupéré avant chaque POST :

```bash
python3 khaleesi.py -u http://host/api/auth/login -e cible@exemple.com -w dico.txt \
    --pre-request-url http://host/login \
    --token-regex 'name="_csrf" value="([^"]+)"' --token-field _csrf
```

Dictionnaire + règles de mutation (mode hybride) :

```bash
python3 khaleesi.py -u ... -e ... -w bases.txt --rules mutations.rule -t 20 --adaptive
```

Fichier de règles (sous-ensemble Hashcat, une règle par ligne) :

```text
# mutations.rule
:            # identité
l            # minuscules
u            # MAJUSCULES
c$!          # Capitalize + suffixe "!"
sa@         # remplace 'a' par '@'
```

Règles supportées : `:` (identité), `l` (minuscules), `u` (MAJUSCULES),
`c` (Capitalize), `r` (inverse), `d` (duplique), `$X` (suffixe X),
`^X` (préfixe X), `sXY` (remplace X par Y), `TN` (bascule la casse à la position N).

Backoff adaptatif face au rate-limiting :

```bash
python3 khaleesi.py -u ... -e ... -w rockyou.txt \
    --adaptive --backoff-factor 1.5 --max-delay 30 --stop-on-429 50
```

Rotation de proxies (un par thread, round-robin) :

```bash
python3 khaleesi.py -u ... -e ... -w ... -t 5 --proxy-list proxies.txt
```

Détection d'énumération de comptes par le temps de réponse :

```bash
python3 khaleesi.py --mode enum -u http://host/api/auth/login \
    -e compte.valide@connu.com --enum-probes 25 --enum-threshold-ms 100
```

## Format du rapport

### JSON (`-o`) — mode brute

```json
{
  "tool": "khaleesi",
  "version": "2.1.0",
  "timestamp": "2026-10-25T10:51:46+00:00",
  "mode": "brute",
  "owasp": {
    "automated_threat": "OAT-007 — Credential Cracking",
    "wstg": "WSTG-ATHN-03 — Testing for Weak Lock Out Mechanism"
  },
  "target_url": "http://127.0.0.1:8377/api/auth/login",
  "method": "POST",
  "identifier": "user@test.com",
  "wordlist": "wordlist.txt",
  "rules_file": null,
  "candidates_total": 21,
  "attempts": 20,
  "errors": 3,
  "rate_limit_hits": 3,
  "threads": 1,
  "delay_seconds": 0.0,
  "adaptive_backoff": true,
  "stop_on_errors": 10,
  "stop_on_429": 0,
  "proxies_used": 0,
  "pre_request_url": "http://127.0.0.1:8377/login",
  "duration_seconds": 6.04,
  "success": true,
  "found_password": "Dracarys!",
  "found_line": 7,
  "stopped_early": false,
  "stopped_reason": null
}
```

| Champ | Description |
|-------|-------------|
| `owasp` | Mappage OWASP : OAT-007 (Credential Cracking) et WSTG-ATHN-03 (Weak Lock Out Mechanism) pour insertion directe dans un rapport de pentest |
| `candidates_total` | Candidats générés (wordlist × règles) |
| `attempts` / `errors` / `rate_limit_hits` | Requêtes envoyées, erreurs réseau, réponses 429 |
| `adaptive_backoff` / `stop_on_429` / `stop_on_errors` | Configuration rate-limiting utilisée |
| `success` / `found_password` / `found_line` | Résultat (ligne = position dans le fichier d'origine) |
| `stopped_early` / `stopped_reason` | Arrêt anticipé et sa cause (`429_limit`, `consecutive_errors`, …) |

### JSON (`-o`) — mode enum

Champs `mode: "enum"`, `owasp.wstg: "WSTG-IDNT-04 — Account Enumeration and
Guessable User Account"`, `probes_per_class`, `threshold_ms`, puis
`results.valid_identifier` / `results.invalid_identifier` avec pour chaque classe
`n`, `mean_ms`, `median_ms`, `stdev_ms`, `min_ms`, `max_ms`, `statuses` ;
`delta_mean_ms`, `relative_delta_pct`, `enumeration_detected` et
`probes_excluded_429_5xx`.

### CSV (`--csv`)

- Mode brute : une ligne de résumé (mêmes champs que le JSON, à plat)
- Mode enum : une ligne par sonde (`probe_index`, `class` valid/invalid,
  `identifier`, `status`, `elapsed_ms`) — prêt pour graphiques/boxplots

## Tests

```bash
python3 -m pytest tests/ -q
```

Couverture : `is_success()` (logique de détection de succès), moteur de règles
de mutation, extraction de token (regex, JSONPath, priorité JSON valide,
fallback regex sur JSON invalide).

## Codes de retour

| Code | Signification |
|------|---------------|
| 0    | Mot de passe trouvé (brute) / énumération détectée (enum) |
| 1    | Dictionnaire épuisé sans succès / pas d'écart de timing significatif |
| 2    | Erreur d'utilisation (arguments, fichiers) |
| 3    | Arrêt anticipé (cible injoignable, limite 429 atteinte, aucune sonde exploitable) |
| 130  | Interruption clavier (Ctrl+C) |

## À propos

**Khaleesi** est un outil de test d'authentification écrit pour les pentesteurs :
un seul fichier Python, une seule dépendance (`requests`), pas de framework.

- **Pourquoi ce nom ?** *Khaleesi* — « reine » en Dothraki, titre de Daenerys
  Targaryen, la Mère des Dragons. Chaque thread de l'outil est un dragon ; quand
  un mot de passe faible se présente, on lui crie *Dracarys*.
- **Philosophie** : rester simple et traçable. Chaque exécution produit un
  rapport JSON auto-descriptif (mappé sur les référentiels OWASP OAT/WSTG) pour
  être copié tel quel dans un rapport de test d'intrusion.
- **Périmètre** : brute force de credentials sur un endpoint HTTP, gestion des
  flows multi-étapes (CSRF), résistance au rate-limiting, détection
  d'énumération de comptes par timing. Ce n'est pas un cracker de hash ni un
  scanner de vulnérabilités généraliste.
- **Historique** : v2.0.0 — moteur brute force multithread ; v2.1.0 —
  streaming du dictionnaire, gestion distincte des 429 (arrêt immédiat +
  backoff adaptatif), rotation de proxies, flows CSRF, règles de mutation,
  mode énumération, exports CSV, suite de tests unitaires.
- **Auteur** : projet personnel, licence MIT — voir [LICENSE](LICENSE).

## Licence

MIT
