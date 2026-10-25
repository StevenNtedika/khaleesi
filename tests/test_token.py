# -*- coding: utf-8 -*-
"""Tests unitaires de l'extraction de token CSRF (regex et JSONPath pointé)."""
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from khaleesi import extract_token  # noqa: E402


def make_args(**overrides):
    defaults = {"token_regex": "", "token_json_path": ""}
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


# --- JSONPath pointé --------------------------------------------------------

def test_json_path_simple_key():
    args = make_args(token_json_path="csrfToken")
    body = '{"csrfToken": "abc123"}'
    assert extract_token(body, args) == "abc123"


def test_json_path_nested():
    args = make_args(token_json_path="data.csrfToken")
    body = '{"data": {"csrfToken": "tok-42"}}'
    assert extract_token(body, args) == "tok-42"


def test_json_path_deep_nested():
    args = make_args(token_json_path="result.meta.token")
    body = '{"result": {"meta": {"token": "deep"}}}'
    assert extract_token(body, args) == "deep"


def test_json_path_missing_key_returns_none():
    args = make_args(token_json_path="data.csrfToken")
    body = '{"data": {"other": 1}}'
    assert extract_token(body, args) is None


def test_json_path_invalid_json_returns_none():
    args = make_args(token_json_path="data.csrfToken")
    assert extract_token("<html>not json</html>", args) is None


def test_json_path_non_string_value_returns_none():
    args = make_args(token_json_path="data.csrfToken")
    body = '{"data": {"csrfToken": 12345}}'
    assert extract_token(body, args) is None


def test_json_path_empty_string_returns_none():
    args = make_args(token_json_path="csrfToken")
    body = '{"csrfToken": ""}'
    assert extract_token(body, args) is None


# --- Regex ------------------------------------------------------------------

def test_regex_with_capture_group():
    args = make_args(token_regex=r'name="_csrf" value="([^"]+)"')
    body = '<form><input name="_csrf" value="a1b2c3"></form>'
    assert extract_token(body, args) == "a1b2c3"


def test_regex_without_capture_group_uses_whole_match():
    args = make_args(token_regex=r"csrf=[a-z0-9]{6}")
    body = "meta: csrf=abc123"
    assert extract_token(body, args) == "csrf=abc123"


def test_regex_no_match_returns_none():
    args = make_args(token_regex=r"token=([a-z0-9]+)")
    assert extract_token("nothing here", args) is None


# --- Priorités --------------------------------------------------------------

def test_valid_json_takes_priority_over_regex():
    args = make_args(token_json_path="token", token_regex=r"regex=([a-z]+)")
    body = '{"token": "from-json", "other": "regex=from-regex"}'
    assert extract_token(body, args) == "from-json"


def test_invalid_json_falls_back_to_regex():
    args = make_args(token_json_path="token", token_regex=r"regex=([a-z]+)")
    body = 'not json, but regex=found'
    assert extract_token(body, args) == "found"
