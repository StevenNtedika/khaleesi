# -*- coding: utf-8 -*-
"""Tests unitaires du moteur de règles de mutation (sous-ensemble Hashcat)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from khaleesi import apply_rule, generate_variants, validate_rule  # noqa: E402


def test_identity_rule():
    assert apply_rule("Password", ":") == "Password"


def test_lowercase():
    assert apply_rule("Password", "l") == "password"


def test_uppercase():
    assert apply_rule("Password", "u") == "PASSWORD"


def test_capitalize():
    assert apply_rule("PaSsWoRd", "c") == "Password"


def test_reverse():
    assert apply_rule("abc", "r") == "cba"


def test_duplicate():
    assert apply_rule("abc", "d") == "abcabc"


def test_append_char():
    assert apply_rule("password", "$1") == "password1"
    assert apply_rule("password", "$!") == "password!"


def test_prepend_char():
    assert apply_rule("password", "^1") == "1password"


def test_replace_chars():
    # sXY : remplace X par Y
    assert apply_rule("password", "sa@") == "p@ssword"


def test_replace_all_occurrences():
    assert apply_rule("banana", "sa@") == "b@n@n@"


def test_toggle_position():
    assert apply_rule("password", "T0") == "Password"
    assert apply_rule("Password", "T0") == "password"


def test_toggle_out_of_bounds_is_noop():
    assert apply_rule("abc", "T9") == "abc"


def test_chained_rules():
    # password -> Password (c) -> Password1 ($1) -> Password1! ($!)
    assert apply_rule("password", "c$1$!") == "Password1!"


def test_validate_accepts_known_rules():
    for rule in (":", "l", "u", "c", "r", "d", "$x", "^x", "sa@", "T3", "c$1$!"):
        validate_rule(rule)  # ne doit pas lever


def test_validate_rejects_unknown():
    try:
        validate_rule("z")
    except ValueError:
        pass
    else:
        raise AssertionError("z doit être rejeté")


def test_validate_rejects_truncated():
    try:
        validate_rule("s")   # s sans ses 2 arguments
    except ValueError:
        pass
    else:
        raise AssertionError("s tronqué doit être rejeté")


def test_generate_variants_dedups_locally():
    variants = generate_variants("pass", ["l", "l", "u"])
    assert variants == ["pass", "PASS"]


def test_generate_variants_skips_empty_results():
    # Une règle ne produit jamais de vide ici, mais un mot vide de base non plus
    variants = generate_variants("ok", [":"])
    assert variants == ["ok"]
