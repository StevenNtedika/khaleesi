# -*- coding: utf-8 -*-
"""Tests unitaires de la fonction critique is_success() de khaleesi.py."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from khaleesi import is_success  # noqa: E402


def make_args(**overrides):
    defaults = {
        "success_key": "success",
        "fail_key": "",
        "success_status": None,
        "success_text": "",
    }
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# --- Détection par clé JSON -------------------------------------------------

def test_success_key_true():
    args = make_args()
    assert is_success(200, '{"success": true, "token": "x"}', args) is True


def test_success_key_false():
    args = make_args()
    assert is_success(200, '{"success": false}', args) is False


def test_success_key_missing():
    args = make_args()
    assert is_success(200, '{"message": "bad credentials"}', args) is False


def test_success_key_absent_treated_as_failure_with_default_status_none():
    args = make_args()
    # Réponse JSON sans la clé attendue et aucun autre critère -> échec
    assert is_success(403, '{"error": "forbidden"}', args) is False


def test_fail_key_short_circuits_even_if_success_key_present():
    args = make_args(fail_key="error")
    assert is_success(200, '{"success": true, "error": "locked"}', args) is False


# --- Détection par code HTTP ------------------------------------------------

def test_success_status_match():
    args = make_args(success_key="", success_status=200)
    assert is_success(200, 'anything', args) is True


def test_success_status_no_match():
    args = make_args(success_key="", success_status=200)
    assert is_success(302, '', args) is False


# --- Détection par texte ----------------------------------------------------

def test_success_text_match():
    args = make_args(success_key="", success_text="Bienvenue")
    assert is_success(200, '<h1>Bienvenue sur votre espace</h1>', args) is True


def test_success_text_no_match():
    args = make_args(success_key="", success_text="Bienvenue")
    assert is_success(200, '<h1>Erreur</h1>', args) is False


# --- Combinaisons -----------------------------------------------------------

def test_success_key_empty_then_text_used():
    args = make_args(success_key="", success_status=None, success_text="OK")
    assert is_success(200, '...OK...', args) is True


def test_success_key_present_but_text_also_defined_matches_any():
    # Si la clé JSON est présente mais absente de la réponse, le critère texte peut décider
    args = make_args(success_key="success", success_text="welcome")
    assert is_success(200, '{"ok": true} welcome', args) is True


def test_invalid_json_with_status_fallback():
    args = make_args(success_key="success", success_status=201)
    # JSON invalide -> on retombe sur le code HTTP
    assert is_success(201, '<html>not json</html>', args) is True


def test_invalid_json_without_fallback_is_failure():
    args = make_args()
    assert is_success(200, 'not json at all', args) is False


def test_empty_body_is_failure():
    args = make_args()
    assert is_success(200, '', args) is False
