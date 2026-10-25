#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
khaleesi.py — Outil de test de résistance des identifiants
(brute force) sur un endpoint d'authentification HTTP.

    « Khaleesi » : mère des dragons. Chaque thread est un dragon,
    et quand un mot de passe faible se présente... Dracarys. 🔥

⚠️  AVERTISSEMENT LÉGAL
    Cet outil est destiné exclusivement aux tests d'intrusion autorisés
    (votre propre infrastructure ou un mandat écrit du propriétaire).
    Toute utilisation non autorisée est illégale. L'auteur décline toute
    responsabilité en cas d'usage abusif.

Nouveautés v2.1.0
-----------------
- Dictionnaire STREAMÉ (générateur) : rockyou.txt comme crackstation.txt
  (15 Go) passent sans saturer la RAM ; --dedup pour dédupliquer en mémoire.
- Règles de mutation façon Hashcat (--rules) : l, u, c, r, d, $X, ^X, sXY, TN.
- Gestion des flows multi-étapes : --pre-request-url récupère un CSRF token
  (regex ou JSONPath) avant chaque tentative, cookies de session persistants.
- Backoff adaptatif sur 429 (--adaptive) : ralentissement exponentiel pour
  cartographier le seuil réel de rate-limiting, au lieu d'abandonner.
- --stop-on-429 N : arrêt immédiat après N réponses 429 (distinct des
  erreurs réseau consécutives).
- Rotation de proxies (--proxy-list) : un proxy par thread, round-robin.
- Mode énumération de comptes (--mode enum) : mesure le temps de réponse
  d'un identifiant valide connu vs des identifiants inexistants (timing).
- Exports JSON enrichi (mappage OWASP OAT/WSTG) et CSV (--csv).

Exemples d'utilisation
----------------------
Mode interactif (l'outil vous demande l'URL, l'email et le dictionnaire) :
    python3 khaleesi.py

Mode 100% CLI (pour scripts / CI) :
    python3 khaleesi.py \
        -u http://localhost:3000/api/auth/login \
        -e cible@exemple.com \
        -w /usr/share/wordlists/rockyou.txt \
        -t 10 --delay 0.1 -o rapport.json

Dictionnaire géant + règles de mutation (sans saturer la RAM) :
    python3 khaleesi.py -u ... -e ... -w crackstation.txt \
        --rules mutations.rule -t 20 --adaptive

Flow avec CSRF token avant chaque POST :
    python3 khaleesi.py -u ... -e ... -w ... \
        --pre-request-url http://host/login \
        --token-json-path data.csrfToken --token-field _csrf

Rotation de proxies (un par thread, round-robin) :
    python3 khaleesi.py -u ... -e ... -w ... -t 5 --proxy-list proxies.txt

Détection d'énumération de comptes par le temps de réponse :
    python3 khaleesi.py --mode enum -u http://host/api/auth/login \
        -e compteur@connu.com --enum-probes 30
"""

import argparse
import csv
import json
import os
import queue
import random
import re
import statistics
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3

__version__ = "2.1.0"
__author__ = "Steven"
TOOL_NAME = "khaleesi"

# --------------------------------------------------------------------------
# Affichage (couleurs ANSI)
# --------------------------------------------------------------------------


class C:
    """Codes couleur ANSI (désactivés si stdout n'est pas un TTY)."""
    ENABLED = sys.stdout.isatty()
    RESET = "\033[0m" if ENABLED else ""
    RED = "\033[91m" if ENABLED else ""
    GREEN = "\033[92m" if ENABLED else ""
    YELLOW = "\033[93m" if ENABLED else ""
    CYAN = "\033[96m" if ENABLED else ""
    BOLD = "\033[1m" if ENABLED else ""
    DIM = "\033[2m" if ENABLED else ""


_print_lock = threading.Lock()


def log(level: str, message: str) -> None:
    """Affiche une ligne horodatée, thread-safe."""
    colors = {"INFO": C.CYAN, "OK": C.GREEN, "WARN": C.YELLOW, "ERR": C.RED, "FAIL": C.DIM}
    color = colors.get(level, "")
    with _print_lock:
        stamp = datetime.now().strftime("%H:%M:%S")
        sys.stdout.write(f"{C.DIM}[{stamp}]{C.RESET} {color}[{level:<4}]{C.RESET} {message}\n")


def progress(line: str) -> None:
    """Met à jour la ligne de progression (une seule ligne du terminal)."""
    with _print_lock:
        sys.stdout.write("\r" + line.ljust(110)[:110])
        sys.stdout.flush()


def clear_progress() -> None:
    with _print_lock:
        sys.stdout.write("\r" + " " * 110 + "\r")


# --------------------------------------------------------------------------
# Analyse des arguments + mode interactif
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Test de résistance des identifiants (brute force) et détection "
            "d'énumération de comptes sur un endpoint d'authentification. "
            "À utiliser UNIQUEMENT sur des systèmes dont vous avez "
            "l'autorisation de test."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=f"{TOOL_NAME} v{__version__} — usage autorisé uniquement.",
    )
    p.add_argument("-u", "--url", help="URL complète de l'endpoint de login (ex: http://host:3000/api/auth/login)")
    p.add_argument("-e", "--email", help="Identifiant (email / login) à tester")
    p.add_argument("-w", "--wordlist", help="Chemin du dictionnaire (une candidature par ligne)")
    p.add_argument("-t", "--threads", type=int, default=1,
                   help="Nombre de threads simultanés (default: %(default)s)")
    p.add_argument("--delay", type=float, default=0.0, metavar="SEC",
                   help="Pause entre chaque requête par thread (default: %(default)s)")
    p.add_argument("--timeout", type=float, default=10.0, metavar="SEC",
                   help="Timeout de chaque requête HTTP (default: %(default)s)")
    p.add_argument("--max-attempts", type=int, default=0, metavar="N",
                   help="Limiter le nombre de candidats testés (0 = tout, default: %(default)s)")
    p.add_argument("--start-line", type=int, default=1, metavar="N",
                   help="Reprendre à partir de la ligne N du dictionnaire (default: %(default)s)")
    p.add_argument("--dedup", action="store_true",
                   help="Dédupliquer les candidats en mémoire (coûteux sur les très gros dictionnaires)")

    # Détection de succès
    g = p.add_argument_group("détection de succès")
    g.add_argument("--success-key", default="success", metavar="KEY",
                   help="Clé JSON dont la valeur vraie indique un succès ('' pour désactiver, default: %(default)s)")
    g.add_argument("--fail-key", default="", metavar="KEY",
                   help="Clé JSON dont la valeur vraie indique un échec (default: %(default)s)")
    g.add_argument("--success-status", type=int, default=None, metavar="CODE",
                   help="Code HTTP considéré comme succès (default: aucun)")
    g.add_argument("--success-text", default="", metavar="STR",
                   help="Chaîne à chercher dans le corps de la réponse (default: %(default)s)")

    # Requête personnalisée
    g = p.add_argument_group("requête personnalisée")
    g.add_argument("--method", default="POST", help="Méthode HTTP (default: %(default)s)")
    g.add_argument("--field-email", default="email", metavar="NAME",
                   help="Nom du champ JSON de l'identifiant (default: %(default)s)")
    g.add_argument("--field-password", default="password", metavar="NAME",
                   help="Nom du champ JSON du mot de passe (default: %(default)s)")
    g.add_argument("--body-template", default="", metavar="TPL",
                   help="Corps brut avec placeholders {EMAIL} {PASSWORD} {TOKEN} (surcharge le JSON par défaut)")
    g.add_argument("-H", "--header", action="append", default=[], metavar="\"K: V\"",
                   help="En-tête HTTP supplémentaire (répétable)")
    p.add_argument("--user-agent", default=f"{TOOL_NAME}/{__version__}", help="User-Agent (default: %(default)s)")
    p.add_argument("--insecure", action="store_true", help="Désactiver la vérification TLS")

    # Authentification multi-étapes (CSRF / session)
    g = p.add_argument_group("authentification multi-étapes")
    g.add_argument("--pre-request-url", default="", metavar="URL",
                   help="URL GET préalable (CSRF/session) faite sur la MÊME session avant chaque tentative")
    g.add_argument("--token-regex", default="", metavar="REGEX",
                   help="Regex avec groupe de capture pour extraire le token de la réponse du pre-request")
    g.add_argument("--token-json-path", default="", metavar="A.B.C",
                   help="Chemin JSON pointé (dot notation, ex: data.csrfToken) pour extraire le token")
    g.add_argument("--token-field", default="", metavar="NAME",
                   help="Injecter le token comme champ JSON du corps de login (ex: _csrf)")
    g.add_argument("--token-header", default="", metavar="NAME",
                   help="Injecter le token comme en-tête HTTP du login (ex: X-CSRF-Token)")

    # Proxies et rotation
    g = p.add_argument_group("proxies & rotation")
    g.add_argument("--proxy", action="append", default=[], metavar="URL",
                   help="Proxy HTTP(S) ou SOCKS (répétable, ex: socks5://127.0.0.1:9050)")
    g.add_argument("--proxy-list", default="", metavar="FILE",
                   help="Fichier de proxies (1 par ligne) : répartition round-robin, 1 proxy par thread")

    # Backoff / rate-limiting
    g = p.add_argument_group("rate-limiting & backoff")
    g.add_argument("--stop-on-errors", type=int, default=10, metavar="N",
                   help="Abandonner après N erreurs réseau/HTTP consécutives "
                        "(0 = illimité, default: %(default)s)")
    g.add_argument("--stop-on-429", type=int, default=0, metavar="N",
                   help="Arrêt IMMÉDIAT après N réponses 429 (cumulées, pas consécutives ; 0 = désactivé, default: %(default)s)")
    g.add_argument("--adaptive", action="store_true",
                   help="Backoff adaptatif : ralentit exponentiellement à chaque 429 au lieu d'abandonner")
    g.add_argument("--backoff-factor", type=float, default=1.5, metavar="F",
                   help="Facteur de ralentissement par 429 reçu (default: %(default)s)")
    g.add_argument("--max-delay", type=float, default=30.0, metavar="SEC",
                   help="Plafond du délai adaptatif (default: %(default)s)")

    # Règles de mutation (dictionnaire hybride)
    g = p.add_argument_group("dictionnaire hybride")
    g.add_argument("--rules", default="", metavar="FILE",
                   help="Fichier de règles de mutation (sous-ensemble Hashcat, 1 règle/ligne). "
                        "Voir README : l u c r d $X ^X sXY TN")

    # Mode énumération de comptes
    g = p.add_argument_group("mode énumération de comptes")
    g.add_argument("--mode", choices=["brute", "enum"], default="brute",
                   help="brute = attaque de dictionnaire ; enum = détection d'énumération par timing (default: %(default)s)")
    g.add_argument("--enum-probes", type=int, default=25, metavar="N",
                   help="Nombre de requêtes par classe (valide / invalide) en mode enum (default: %(default)s)")
    g.add_argument("--enum-threshold-ms", type=float, default=100.0, metavar="MS",
                   help="Écart de temps de réponse moyen jugé significatif (default: %(default)s)")
    g.add_argument("--enum-fake-domain", default="khaleesi.invalid", metavar="DOM",
                   help="Domaine factice pour les identifiants inexistants (default: %(default)s)")

    # Comportement / sortie
    g = p.add_argument_group("comportement & sortie")
    g.add_argument("-o", "--output", metavar="FILE", help="Rapport de résultat au format JSON")
    g.add_argument("--csv", default="", metavar="FILE",
                   help="Export CSV complémentaire (résumé en mode brute, 1 ligne par sonde en mode enum)")
    g.add_argument("--quiet", action="store_true", help="Masquer les lignes de progression")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def prompt_if_missing(args: argparse.Namespace) -> None:
    """Demande à l'utilisateur les valeurs manquantes (mode interactif)."""
    print(f"\n{C.BOLD}{TOOL_NAME} v{__version__}{C.RESET} — {C.YELLOW}"
          f"test de résistance des identifiants{C.RESET}")
    print(f"{C.RED}Rappel : à utiliser uniquement sur un système que vous êtes autorisé à tester.{C.RESET}\n")
    if not args.url:
        args.url = input("URL de l'endpoint de login (ex: http://localhost:3000/api/auth/login) : ").strip()
    if not args.email:
        args.email = input("Identifiant / email à tester : ").strip()
    if args.mode == "brute" and not args.wordlist:
        args.wordlist = input("Chemin du dictionnaire (ex: /usr/share/wordlists/rockyou.txt) : ").strip()
        if os.path.exists(args.wordlist):
            try:
                total = sum(1 for _ in open(args.wordlist, "rb"))
                print(f"{C.DIM}[i] Dictionnaire trouvé : {total} lignes.{C.RESET}")
            except OSError:
                pass


def validate_args(args: argparse.Namespace) -> None:
    if args.mode == "brute" and (not args.url or not args.wordlist or not args.email):
        log("ERR", "URL, identifiant et dictionnaire sont obligatoires en mode brute (-u / -e / -w).")
        sys.exit(2)
    if args.mode == "enum" and (not args.url or not args.email):
        log("ERR", "URL et identifiant valide connu sont obligatoires en mode enum (-u / -e).")
        sys.exit(2)
    parsed = urlparse(args.url)
    if not args.url or parsed.scheme not in ("http", "https") or not parsed.netloc:
        log("ERR", f"URL invalide : {args.url!r} (doit commencer par http:// ou https://).")
        sys.exit(2)
    if args.mode == "brute" and not os.path.isfile(args.wordlist):
        log("ERR", f"Dictionnaire introuvable : {args.wordlist}")
        sys.exit(2)
    if args.threads < 1 or args.threads > 256:
        log("ERR", "Le nombre de threads doit être entre 1 et 256.")
        sys.exit(2)
    if args.stop_on_errors < 0:
        log("ERR", "--stop-on-errors doit être positif.")
        sys.exit(2)
    if args.stop_on_429 < 0:
        log("ERR", "--stop-on-429 doit être positif ou 0 (désactivé).")
        sys.exit(2)
    if args.backoff_factor <= 1.0:
        log("ERR", "--backoff-factor doit être strictement supérieur à 1.0.")
        sys.exit(2)
    if args.max_delay < args.delay:
        log("ERR", "--max-delay doit être >= au délai de base (--delay).")
        sys.exit(2)
    if args.enum_probes < 2:
        log("ERR", "--enum-probes doit être au moins 2 (une mesure statistique exige plusieurs échantillons).")
        sys.exit(2)
    if args.mode == "brute" and args.body_template and ("{PASSWORD}" not in args.body_template):
        log("ERR", "--body-template doit contenir le placeholder {PASSWORD}.")
        sys.exit(2)

    headers = {}
    for h in args.header:
        if ":" not in h:
            log("ERR", f"En-tête invalide (format attendu \"Clé: Valeur\") : {h}")
            sys.exit(2)
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    args.extra_headers = headers

    # Pool de proxies (fusion --proxy et --proxy-list)
    args.proxy_pool = list(args.proxy)
    if args.proxy_list:
        if not os.path.isfile(args.proxy_list):
            log("ERR", f"Fichier de proxies introuvable : {args.proxy_list}")
            sys.exit(2)
        with open(args.proxy_list, "r", encoding="utf-8") as fh:
            for line in fh:
                prx = line.strip()
                if prx and not prx.startswith("#"):
                    args.proxy_pool.append(prx)
    if args.proxy_pool and args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Authentification multi-étapes : cohérence
    if args.pre_request_url:
        pr = urlparse(args.pre_request_url)
        if pr.scheme not in ("http", "https") or not pr.netloc:
            log("ERR", f"--pre-request-url invalide : {args.pre_request_url!r}")
            sys.exit(2)
        if not args.token_regex and not args.token_json_path:
            log("ERR", "--pre-request-url exige --token-regex ou --token-json-path pour extraire le token.")
            sys.exit(2)
    elif args.token_field or args.token_header:
        log("ERR", "--token-field / --token-header exigent --pre-request-url (aucune source de token).")
        sys.exit(2)
    if args.body_template and "{TOKEN}" in args.body_template and not args.pre_request_url:
        log("ERR", "Placeholder {TOKEN} dans --body-template mais --pre-request-url est absent.")
        sys.exit(2)

    # Règles de mutation
    args.rules_list = []
    if args.rules:
        if not os.path.isfile(args.rules):
            log("ERR", f"Fichier de règles introuvable : {args.rules}")
            sys.exit(2)
        try:
            args.rules_list = load_rules(args.rules)
        except ValueError as exc:
            log("ERR", f"Règle invalide dans {args.rules} : {exc}")
            sys.exit(2)
        if not args.rules_list:
            log("ERR", f"Aucune règle valide dans {args.rules}.")
            sys.exit(2)


# --------------------------------------------------------------------------
# Détection de succès
# --------------------------------------------------------------------------


def is_success(status: int, body: str, args: argparse.Namespace) -> bool:
    """Décide si une réponse correspond à une authentification réussie."""
    # 1) Clé JSON de succès
    if args.success_key:
        try:
            data = json.loads(body) if body else None
        except (json.JSONDecodeError, ValueError):
            data = None
        if isinstance(data, dict):
            if args.fail_key and data.get(args.fail_key):
                return False
            if data.get(args.success_key):
                return True
            if args.success_status is None and args.success_text == "":
                return False  # réponse JSON sans la clé attendue -> échec
    # 2) Code HTTP de succès
    if args.success_status is not None and status == args.success_status:
        return True
    # 3) Chaîne dans le corps
    if args.success_text and args.success_text in body:
        return True
    return False


# --------------------------------------------------------------------------
# Extraction de token (flow multi-étapes)
# --------------------------------------------------------------------------


def extract_token(body: str, args: argparse.Namespace) -> str | None:
    """Extrait un token d'une réponse : JSONPath pointé, sinon regex.

    Si le corps n'est pas du JSON valide, on retombe sur la regex (un endpoint
    peut servir du HTML au pre-request)."""
    if args.token_json_path:
        try:
            data = json.loads(body) if body else None
        except (json.JSONDecodeError, ValueError):
            data = "__invalid__"  # retombera sur la regex plus bas
        else:
            if not isinstance(data, dict):
                return None
            current = data
            for part in args.token_json_path.split("."):
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            return current if isinstance(current, str) and current else None
    if args.token_regex:
        match = re.search(args.token_regex, body)
        if match:
            token = match.group(1) if match.groups() else match.group(0)
            return token or None
    return None


def fetch_token(session: requests.Session, args: argparse.Namespace) -> str | None:
    """Fait le GET préalable (même session → cookies partagés) et extrait le token."""
    response = session.get(args.pre_request_url, timeout=args.timeout)
    return extract_token(response.text, args)


# --------------------------------------------------------------------------
# Règles de mutation (sous-ensemble Hashcat)
# --------------------------------------------------------------------------


def load_rules(path: str) -> list[str]:
    """Charge les règles (1 par ligne, # et lignes vides ignorés)."""
    rules = []
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            rule = raw.rstrip("\r\n")
            if not rule or rule.lstrip().startswith("#"):
                continue
            validate_rule(rule)
            rules.append(rule)
    return rules


def validate_rule(rule: str) -> None:
    """Valide la syntaxe d'une règle (lève ValueError si invalide)."""
    i = 0
    while i < len(rule):
        c = rule[i]
        if c in (":", "l", "u", "c", "r", "d"):
            i += 1
        elif c in ("$", "^") and i + 1 < len(rule):
            i += 2  # caractère littéral
        elif c == "s" and i + 2 < len(rule):
            i += 3  # sXY : remplacer X par Y
        elif c == "T" and i + 1 < len(rule) and rule[i + 1].isdigit():
            i += 2  # TN : toggle à la position N
        else:
            raise ValueError(f"opérande inconnue ou tronquée dans {rule!r} (position {i})")


def apply_rule(word: str, rule: str) -> str:
    """Applique une règle de mutation à un mot. Règles supportées :
    : (identité)  l (minuscules)  u (MAJUSCULES)  c (Capitalize)
    r (reverse)   d (duplique)    $X (suffixe X)  ^X (préfixe X)
    sXY (remplace X par Y)        TN (toggle la casse à la position N)
    """
    result = word
    i = 0
    while i < len(rule):
        c = rule[i]
        if c == ":":
            pass
        elif c == "l":
            result = result.lower()
        elif c == "u":
            result = result.upper()
        elif c == "c":
            result = result.lower().capitalize()
        elif c == "r":
            result = result[::-1]
        elif c == "d":
            result = result + result
        elif c == "$":
            i += 1
            result += rule[i]
        elif c == "^":
            i += 1
            result = rule[i] + result
        elif c == "s":
            old, new = rule[i + 1], rule[i + 2]
            result = result.replace(old, new)
            i += 2
        elif c == "T":
            n = int(rule[i + 1])
            if 0 <= n < len(result):
                ch = result[n]
                result = result[:n] + (ch.lower() if ch.isupper() else ch.upper()) + result[n + 1:]
            i += 1
        i += 1
    return result


def generate_variants(word: str, rules: list[str]) -> list[str]:
    """Applique chaque règle au mot de base (dédupliqué localement)."""
    variants, seen = [], set()
    for rule in rules:
        variant = apply_rule(word, rule)
        if variant and variant not in seen:
            seen.add(variant)
            variants.append(variant)
    return variants


# --------------------------------------------------------------------------
# Dictionnaire streamé (générateur)
# --------------------------------------------------------------------------


def iter_candidates(args: argparse.Namespace, seen: set | None):
    """Générateur de candidats (lineno, mot) — ne charge PAS le fichier en mémoire.

    - ignore les lignes vides et les lignes < --start-line
    - applique les règles de mutation si --rules est fourni
    - déduplique seulement si `seen` est fourni (--dedup)
    """
    with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as fh:
        for lineno, raw in enumerate(fh, 1):
            if lineno < args.start_line:
                continue
            base = raw.rstrip("\r\n")
            if not base:
                continue
            if args.rules_list:
                variants = generate_variants(base, args.rules_list)
                if not variants:
                    variants = [base]
                for variant in variants:
                    if seen is not None:
                        if variant in seen:
                            continue
                        seen.add(variant)
                    yield lineno, variant
            else:
                if seen is not None:
                    if base in seen:
                        continue
                    seen.add(base)
                yield lineno, base


# --------------------------------------------------------------------------
# Statistiques partagées + backoff adaptatif
# --------------------------------------------------------------------------


class AdaptiveDelay:
    """Délai adaptatif partagé : augmente exponentiellement à chaque 429,
    redescend doucement vers le délai de base quand la cible respire."""

    def __init__(self, base: float, factor: float, cap: float):
        self.lock = threading.Lock()
        self.base = base
        self.factor = factor
        self.cap = cap
        # Plancher : un délai de base nul doit quand même pouvoir ralentir
        self.floor = 0.25 if base < 0.25 else base
        self.value = base

    def bump(self) -> float:
        with self.lock:
            self.value = min(self.cap, max(self.value, self.floor) * self.factor)
            return self.value

    def decay(self) -> float:
        with self.lock:
            self.value = max(self.base, self.value / self.factor)
            return self.value

    def get(self) -> float:
        with self.lock:
            return self.value


class Stats:
    """Compteurs partagés entre threads (thread-safe)."""

    def __init__(self, stop_on_errors: int = 0, stop_on_429: int = 0):
        self.lock = threading.Lock()
        self.total = 0                # total ENQUEUE, alimenté par le feeder
        self.stop_on_errors = stop_on_errors
        self.stop_on_429 = stop_on_429
        self.attempts = 0
        self.errors = 0
        self.rate_limit_hits = 0
        self.consecutive_errors = 0
        self.found = None       # (password, line_number, status)
        self.last_status = None
        self.stopped_reason = ""
        self.stop = threading.Event()

    def bump_total(self, n: int = 1) -> None:
        with self.lock:
            self.total += n

    def tick(self, status: int, ok: bool, error: bool = False,
             found: tuple | None = None) -> None:
        """error=True uniquement pour une erreur transport/serveur (pas un échec de login)."""
        with self.lock:
            self.attempts += 1
            self.last_status = status
            if ok:
                self.consecutive_errors = 0
            elif error:
                self.errors += 1
                self.consecutive_errors += 1
            else:
                self.consecutive_errors = 0
            if found and self.found is None:
                self.found = found

    def note_429(self) -> None:
        """Compte un 429 et déclenche l'arrêt immédiat si --stop-on-429 est atteint."""
        with self.lock:
            self.rate_limit_hits += 1
            if self.stop_on_429 and self.rate_limit_hits >= self.stop_on_429:
                self.stop.set()
                self.stopped_reason = f"stop-on-429 ({self.stop_on_429} réponses 429)"

    def should_stop(self) -> bool:
        with self.lock:
            if self.found or self.stop.is_set():
                return True
            if self.stop_on_errors and self.consecutive_errors >= self.stop_on_errors:
                self.stop.set()
                if not self.stopped_reason:
                    self.stopped_reason = (f"stop-on-errors ({self.stop_on_errors} erreurs consécutives)")
                return True
            return False


# --------------------------------------------------------------------------
# Moteur de test (mode brute)
# --------------------------------------------------------------------------


def make_session(args: argparse.Namespace, proxy: str | None = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "application/json, text/plain, */*",
        "Connection": "keep-alive",
    })
    s.headers.update(args.extra_headers)
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    elif args.proxy_pool:
        prx = args.proxy_pool[0]
        s.proxies.update({"http": prx, "https": prx})
    s.verify = not args.insecure
    return s


def build_request(args: argparse.Namespace, password: str,
                 token: str | None = None,
                 identifier: str | None = None):
    """Construit (url, kwargs) pour un candidat donné.

    `identifier` permet de remplacer l'identifiant (mode enum : sonde
    valide vs inexistante) ; par défaut on utilise args.email.
    """
    email = identifier if identifier is not None else args.email
    if args.body_template:
        body = (args.body_template
                .replace("{EMAIL}", email)
                .replace("{PASSWORD}", password)
                .replace("{TOKEN}", token or ""))
        kwargs = {"data": body}
    else:
        payload = {args.field_email: email, args.field_password: password}
        if token and args.token_field:
            payload[args.token_field] = token
        kwargs = {"json": payload}
    if token and args.token_header:
        kwargs["headers"] = {args.token_header: token}
    return args.url, kwargs


def feeder(words_q: "queue.Queue[tuple[int, str]]", stats: Stats,
           args: argparse.Namespace) -> None:
    """Alimente la file depuis le disque (streaming) dans un thread dédié."""
    seen = set() if args.dedup else None
    enqueued = 0
    for item in iter_candidates(args, seen):
        if stats.stop.is_set():
            break
        if args.max_attempts and stats.total >= args.max_attempts:
            break
        words_q.put(item)
        enqueued += 1
        if enqueued % 1000 == 0:
            stats.bump_total(1000)
    stats.bump_total(enqueued % 1000)
    stats.feeder_done.set()


def worker(worker_id: int, words_q: "queue.Queue[tuple[int, str]]", stats: Stats,
           args: argparse.Namespace, session: requests.Session,
           adaptive: AdaptiveDelay) -> None:
    last_rl_warn = 0.0
    while not stats.should_stop():
        try:
            lineno, password = words_q.get(timeout=0.25)
        except queue.Empty:
            if stats.feeder_done.is_set() and words_q.empty():
                return
            continue
        try:
            token = None
            if args.pre_request_url:
                try:
                    token = fetch_token(session, args)
                except requests.RequestException as exc:
                    stats.tick(0, ok=False, error=True)
                    log("ERR", f"Pre-request échoué ({exc.__class__.__name__}) : {exc}")
                    time.sleep(1.0)
                    continue
                if token is None:
                    stats.tick(0, ok=False, error=True)
                    log("ERR", "Token introuvable dans la réponse du pre-request.")
                    time.sleep(1.0)
                    continue

            url, kwargs = build_request(args, password, token=token)
            response = session.request(args.method, url, timeout=args.timeout, **kwargs)
            ok = is_success(response.status_code, response.text, args)
            server_issue = response.status_code >= 500 or response.status_code == 429
            stats.tick(response.status_code, ok, error=server_issue,
                       found=(password, lineno, response.status_code) if ok else None)
            if ok:
                stats.stop.set()
            elif response.status_code == 429:
                stats.note_429()
                if args.adaptive:
                    current = adaptive.bump()
                    log("WARN", f"429 reçu — backoff adaptatif : délai porté à {current:.2f}s.")
                    # Le candidat n'a pas été réellement testé : on le remet en file
                    if not stats.should_stop():
                        words_q.put((lineno, password))
                elif time.monotonic() - last_rl_warn > 5.0:
                    last_rl_warn = time.monotonic()
                    log("WARN", "Réponse 429 — possible rate-limiting, réduisez la vitesse (-t/--delay).")
                time.sleep(1.0)  # pause fixe minimale après un 429
            elif response.status_code >= 500:
                log("WARN", f"Réponse {response.status_code} — erreur serveur cible.")
            else:
                if args.adaptive:
                    adaptive.decay()
            if not args.quiet and C.ENABLED and worker_id == 0:
                total = max(stats.total, 1)
                pct = min(stats.attempts * 100 / total, 100.0)
                rl = f", {stats.rate_limit_hits} x 429" if stats.rate_limit_hits else ""
                progress(f"[{pct:5.1f}%] {stats.attempts}/{stats.total} essais — "
                         f"statut HTTP {stats.last_status}{rl}")
        except requests.RequestException as exc:
            stats.tick(0, ok=False, error=True)
            log("ERR", f"Requête échouée ({exc.__class__.__name__}) : {exc}")
            time.sleep(1.0)  # backoff simple en cas d'erreur réseau
        finally:
            words_q.task_done()
            delay = args.delay
            if args.adaptive:
                delay = max(delay, adaptive.get())
            if delay > 0:
                time.sleep(delay)


def run(args: argparse.Namespace) -> int:
    stats = Stats(args.stop_on_errors, args.stop_on_429)
    stats.feeder_done = threading.Event()
    words_q: "queue.Queue[tuple[int, str]]" = queue.Queue(maxsize=10000)

    log("INFO", f"Cible   : {args.url}")
    log("INFO", f"Compte  : {args.email}")
    log("INFO", f"Dico    : {args.wordlist} (streamé, démarrage ligne {args.start_line}"
                 f"{f', {len(args.rules_list)} règles de mutation' if args.rules_list else ''})")
    log("INFO", f"Config  : {args.threads} thread(s), timeout {args.timeout}s, délai {args.delay}s"
                 f"{', backoff adaptatif' if args.adaptive else ''}"
                 f"{f', stop-on-429={args.stop_on_429}' if args.stop_on_429 else ''}"
                 f"{f', {len(args.proxy_pool)} proxy(ies)' if args.proxy_pool else ''}")

    start = time.time()
    feeder_thread = threading.Thread(target=feeder, args=(words_q, stats, args), daemon=True)
    feeder_thread.start()

    sessions = []
    for i in range(args.threads):
        proxy = args.proxy_pool[i % len(args.proxy_pool)] if args.proxy_pool else None
        sessions.append(make_session(args, proxy))
    adaptive = AdaptiveDelay(args.delay, args.backoff_factor, args.max_delay)
    exit_code = 1
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            for i in range(args.threads):
                pool.submit(worker, i, words_q, stats, args, sessions[i], adaptive)
    except KeyboardInterrupt:
        clear_progress()
        log("WARN", "Interruption clavier — arrêt demandé...")
        stats.stop.set()
        return 130
    feeder_thread.join(timeout=30.0)
    clear_progress()
    elapsed = time.time() - start

    rate = stats.attempts / elapsed if elapsed else 0.0
    log("INFO", f"Terminé en {elapsed:.2f}s — {stats.attempts} requêtes ({rate:.1f} req/s), "
                f"{stats.errors} erreur(s), {stats.rate_limit_hits} x 429.")

    if stats.found:
        password, lineno, status = stats.found
        log("OK", f"SUCÈS : mot de passe trouvé '{password}' "
                 f"(ligne {lineno}, statut HTTP {status}, {elapsed:.2f}s)")
        if args.output:
            write_report(args, stats, password, lineno, elapsed)
        if args.csv:
            write_csv_brute(args, stats, password, lineno, elapsed)
        return 0

    log("WARN", "Aucun mot de passe trouvé dans ce dictionnaire.")
    if stats.stop.is_set() and not stats.found:
        log("ERR", f"Arrêt anticipé : {stats.stopped_reason or 'erreurs consécutives'} "
                   "(cible injoignable, bloquée ou rate-limiting).")
        if args.output:
            write_report(args, stats, None, None, elapsed)
        if args.csv:
            write_csv_brute(args, stats, None, None, elapsed)
        return 3
    if args.output:
        write_report(args, stats, None, None, elapsed)
    if args.csv:
        write_csv_brute(args, stats, None, None, elapsed)
    return 1


# --------------------------------------------------------------------------
# Moteur de test (mode énumération de comptes)
# --------------------------------------------------------------------------


def random_password(length: int = 12) -> str:
    alphabet = string.ascii_letters + string.digits + "!#%+"
    return "".join(random.choice(alphabet) for _ in range(length))


def fake_identifier(args: argparse.Namespace, index: int) -> str:
    """Identifiant inexistant mais au format plausible de la cible."""
    if "@" in args.email:
        return f"khaleesi-probe-{index}@{args.enum_fake_domain}"
    return f"khaleesi-probe-{index}"


def timing_probe(session: requests.Session, args: argparse.Namespace,
                 identifier: str) -> tuple[float, int]:
    """Une requête de login chronométrée (POST uniquement, token préalable non compté)."""
    password = random_password()
    token = None
    if args.pre_request_url:
        token = fetch_token(session, args)
    url, kwargs = build_request(args, password, token=token, identifier=identifier)
    started = time.perf_counter()
    response = session.request(args.method, url, timeout=args.timeout, **kwargs)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return elapsed_ms, response.status_code


def describe(samples: list[float], statuses: list[int]) -> dict:
    return {
        "n": len(samples),
        "mean_ms": round(statistics.mean(samples), 2),
        "median_ms": round(statistics.median(samples), 2),
        "stdev_ms": round(statistics.stdev(samples), 2) if len(samples) > 1 else 0.0,
        "min_ms": round(min(samples), 2),
        "max_ms": round(max(samples), 2),
        "statuses": sorted(set(statuses)),
    }


def run_enum(args: argparse.Namespace) -> int:
    probes = args.enum_probes
    log("INFO", f"Cible   : {args.url}")
    log("INFO", f"Compte valide connu : {args.email}")
    log("INFO", f"Sondes : {probes} par classe (valide vs {args.enum_fake_domain}), "
                f"seuil {args.enum_threshold_ms} ms")

    session = make_session(args)
    valid_samples, invalid_samples = [], []
    valid_statuses, invalid_statuses = [], []
    try:
        for i in range(probes):
            ms, status = timing_probe(session, args, args.email)
            valid_samples.append(ms)
            valid_statuses.append(status)
            ms, status = timing_probe(session, args, fake_identifier(args, i))
            invalid_samples.append(ms)
            invalid_statuses.append(status)
            if not args.quiet:
                progress(f"[{i + 1}/{probes}] sondes valides/inexistantes envoyées")
            if args.delay:
                time.sleep(args.delay)
    except KeyboardInterrupt:
        clear_progress()
        log("WARN", "Interruption clavier — arrêt demandé.")
        return 130
    except requests.RequestException as exc:
        clear_progress()
        log("ERR", f"Cible injoignable : {exc}")
        if args.output:
            write_report_enum(args, valid_samples, valid_statuses,
                              invalid_samples, invalid_statuses, False)
        return 3
    clear_progress()

    # Les 429/5xx sont des réponses transitoires (rate-limiting, serveur surchargé)
    # sans valeur de timing exploitable : on les exclut des statistiques
    # (ils restent visibles dans le CSV et les statuts bruts).
    def clean(samples, statuses):
        pairs = [(ms, st) for ms, st in zip(samples, statuses)
                 if st != 429 and st < 500]
        excluded = len(samples) - len(pairs)
        if excluded:
            log("INFO", f"{excluded} sonde(s) 429/5xx exclue(s) des statistiques de timing.")
        if not pairs:
            return None, None
        return (list(p[0] for p in pairs), list(p[1] for p in pairs))

    valid_clean, valid_statuses_clean = clean(valid_samples, valid_statuses)
    invalid_clean, invalid_statuses_clean = clean(invalid_samples, invalid_statuses)
    stats_valid = describe(valid_clean, valid_statuses_clean) if valid_clean else None
    stats_invalid = describe(invalid_clean, invalid_statuses_clean) if invalid_clean else None
    if stats_valid is None or stats_invalid is None:
        log("ERR", "Aucune sonde exploitable (toutes en 429/5xx ?) — augmentez "
                    "l'intervalle entre sondes (--delay) ou réduisez --enum-probes.")
        if args.output:
            write_report_enum(args, valid_samples, valid_statuses,
                              invalid_samples, invalid_statuses, False)
        return 3
    delta_mean = stats_valid["mean_ms"] - stats_invalid["mean_ms"]
    delta_median = stats_valid["median_ms"] - stats_invalid["median_ms"]
    relative = (abs(delta_mean) / stats_invalid["mean_ms"] * 100.0) if stats_invalid["mean_ms"] else 0.0
    detected = abs(delta_mean) >= args.enum_threshold_ms

    log("INFO", f"Valide    : moyenne {stats_valid['mean_ms']:.1f} ms "
                f"(médiane {stats_valid['median_ms']:.1f} ms, écart-type {stats_valid['stdev_ms']:.1f})")
    log("INFO", f"Inexistant: moyenne {stats_invalid['mean_ms']:.1f} ms "
                f"(médiane {stats_invalid['median_ms']:.1f} ms, écart-type {stats_invalid['stdev_ms']:.1f})")
    log("INFO", f"Écart moyen : {delta_mean:+.1f} ms ({relative:.1f} %)")

    if detected:
        log("OK", f"ÉNUMÉRATION PROBABLE : écart de {abs(delta_mean):.1f} ms "
                 f">= seuil {args.enum_threshold_ms:.0f} ms — l'endpoint révèle l'existence du compte par son temps de réponse.")
        if set(valid_statuses) != set(invalid_statuses):
            log("INFO", f"Statuts HTTP différents aussi (valide {valid_statuses} vs "
                        f"inexistant {invalid_statuses}) — signal encore plus fort.")
    else:
        log("WARN", f"Aucun écart significatif (< {args.enum_threshold_ms:.0f} ms) — "
                    "pas d'énumération par timing détectée à ce seuil.")

    if args.output:
        write_report_enum(args, valid_samples, valid_statuses,
                          invalid_samples, invalid_statuses, detected)
    if args.csv:
        write_csv_enum(args, valid_samples, valid_statuses,
                       invalid_samples, invalid_statuses)
    return 0 if detected else 1


# --------------------------------------------------------------------------
# Rapports
# --------------------------------------------------------------------------

OWASP_BRUTE = {
    "automated_threat": "OAT-007 — Credential Cracking",
    "wstg": "WSTG-ATHN-03 — Testing for Weak Lock Out Mechanism",
}
OWASP_ENUM = {
    "wstg": "WSTG-IDNT-04 — Account Enumeration and Guessable User Account",
}


def write_report(args: argparse.Namespace, stats: Stats, password, lineno, elapsed: float) -> None:
    """Écrit le rapport JSON final (mode brute)."""
    report = {
        "tool": TOOL_NAME,
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "brute",
        "owasp": OWASP_BRUTE,
        "target_url": args.url,
        "method": args.method,
        "identifier": args.email,
        "wordlist": args.wordlist,
        "rules_file": args.rules or None,
        "candidates_total": stats.total,
        "attempts": stats.attempts,
        "errors": stats.errors,
        "rate_limit_hits": stats.rate_limit_hits,
        "threads": args.threads,
        "delay_seconds": args.delay,
        "adaptive_backoff": args.adaptive,
        "stop_on_errors": args.stop_on_errors,
        "stop_on_429": args.stop_on_429,
        "proxies_used": len(args.proxy_pool),
        "pre_request_url": args.pre_request_url or None,
        "duration_seconds": round(elapsed, 2),
        "success": bool(stats.found),
        "found_password": password,
        "found_line": lineno,
        "stopped_early": stats.stop.is_set() and not stats.found,
        "stopped_reason": stats.stopped_reason or None,
    }
    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        log("INFO", f"Rapport JSON écrit : {args.output}")
    except OSError as exc:
        log("ERR", f"Impossible d'écrire le rapport {args.output} : {exc}")


def write_csv_brute(args: argparse.Namespace, stats: Stats, password, lineno, elapsed: float) -> None:
    """Export CSV (mode brute) : une ligne résumé, compatible tableur/rapport."""
    try:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["timestamp", "mode", "target_url", "method", "identifier",
                             "wordlist", "rules_file", "candidates_total", "attempts",
                             "errors", "rate_limit_hits", "threads", "duration_seconds",
                             "success", "found_password", "found_line", "stopped_early",
                             "stopped_reason"])
            writer.writerow([datetime.now(timezone.utc).isoformat(), "brute", args.url,
                             args.method, args.email, args.wordlist, args.rules or "",
                             stats.total, stats.attempts, stats.errors,
                             stats.rate_limit_hits, args.threads, round(elapsed, 2),
                             bool(stats.found), password or "", lineno or "",
                             stats.stop.is_set() and not stats.found,
                             stats.stopped_reason or ""])
        log("INFO", f"Rapport CSV écrit : {args.csv}")
    except OSError as exc:
        log("ERR", f"Impossible d'écrire le CSV {args.csv} : {exc}")


def write_report_enum(args: argparse.Namespace, valid_samples: list[float],
                      valid_statuses: list[int], invalid_samples: list[float],
                      invalid_statuses: list[int], detected: bool) -> None:
    """Rapport JSON (mode énumération)."""
    stats_valid = describe(valid_samples, valid_statuses) if valid_samples else None
    stats_invalid = describe(invalid_samples, invalid_statuses) if invalid_samples else None
    delta_mean = (stats_valid["mean_ms"] - stats_invalid["mean_ms"]) if stats_valid and stats_invalid else 0.0
    relative = (abs(delta_mean) / stats_invalid["mean_ms"] * 100.0) if stats_invalid and stats_invalid["mean_ms"] else 0.0
    report = {
        "tool": TOOL_NAME,
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "mode": "enum",
        "owasp": OWASP_ENUM,
        "target_url": args.url,
        "method": args.method,
        "identifier_valid": args.email,
        "fake_domain": args.enum_fake_domain,
        "probes_per_class": args.enum_probes,
        "threshold_ms": args.enum_threshold_ms,
        "results": {
            "valid_identifier": stats_valid,
            "invalid_identifier": stats_invalid,
        },
        "probes_excluded_429_5xx": {
            "valid": len(valid_samples) - len([s for s in zip(valid_samples, valid_statuses)
                                                if s[1] != 429 and s[1] < 500]),
            "invalid": len(invalid_samples) - len([s for s in zip(invalid_samples, invalid_statuses)
                                                   if s[1] != 429 and s[1] < 500]),
        },
        "delta_mean_ms": round(delta_mean, 2),
        "relative_delta_pct": round(relative, 2),
        "enumeration_detected": detected,
    }
    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        log("INFO", f"Rapport JSON écrit : {args.output}")
    except OSError as exc:
        log("ERR", f"Impossible d'écrire le rapport {args.output} : {exc}")


def write_csv_enum(args: argparse.Namespace, valid_samples: list[float],
                   valid_statuses: list[int], invalid_samples: list[float],
                   invalid_statuses: list[int]) -> None:
    """Export CSV (mode énumération) : 1 ligne par sonde, prêt pour graphiques."""
    try:
        with open(args.csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["probe_index", "class", "identifier", "status", "elapsed_ms"])
            for i, (ms, status) in enumerate(zip(valid_samples, valid_statuses)):
                writer.writerow([i, "valid", args.email, status, round(ms, 2)])
            for i, (ms, status) in enumerate(zip(invalid_samples, invalid_statuses)):
                writer.writerow([i, "invalid", fake_identifier(args, i), status, round(ms, 2)])
        log("INFO", f"Rapport CSV écrit : {args.csv}")
    except OSError as exc:
        log("ERR", f"Impossible d'écrire le CSV {args.csv} : {exc}")


# --------------------------------------------------------------------------
# Point d'entrée
# --------------------------------------------------------------------------


def main() -> int:
    title = f"{TOOL_NAME} v{__version__} — mère des dragons".center(46)
    banner = f"""
{C.CYAN}╔══════════════════════════════════════════════╗
║{C.BOLD}{title}{C.RESET}{C.CYAN}║
╚══════════════════════════════════════════════╝{C.RESET}"""
    print(banner)
    args = build_parser().parse_args()
    prompt_if_missing(args)
    validate_args(args)
    if args.mode == "enum":
        return run_enum(args)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
