"""Unit tests for KaraQargha OSINT modules.

Ensures phone and IP modules, breach module, social module, core utilities,
and reports work offline without network dependencies.
"""

from __future__ import annotations

import json
import os
from unittest import mock
import pytest

from karagargha.core import colors
from karagargha.core.report import generate_json_report, generate_txt_report, save_report
from karagargha.core.spinner import Spinner
from karagargha.main import build_parser
from karagargha.modules.breach import scan_breaches
from karagargha.modules.ip import scan_ip
from karagargha.modules.phone import scan_phone
from karagargha.modules.social import scan_social


# =========================================================================
# 1. PHONE MODULE TESTS (Completely Offline / No Network)
# =========================================================================

def test_phone_valid_us_number() -> None:
    """Test phone module on a valid US phone number."""
    number = "+14155552671"
    result_text = scan_phone(number, raw=False)
    assert isinstance(result_text, str)
    assert "+14155552671" in result_text
    assert "Valid" in result_text
    assert "San Francisco" in result_text or "CA" in result_text or "Region" in result_text

    result_raw = scan_phone(number, raw=True)
    assert isinstance(result_raw, dict)
    assert result_raw.get("valid") is True
    assert result_raw.get("e164") == "+14155552671"
    assert result_raw.get("country_code") == 1
    assert "timezone" in result_raw


def test_phone_valid_uk_number() -> None:
    """Test phone module on a valid UK number."""
    number = "+442071838750"
    result_text = scan_phone(number, raw=False)
    assert isinstance(result_text, str)
    assert "+442071838750" in result_text
    assert "London" in result_text or "United Kingdom" in result_text or "Valid" in result_text

    result_raw = scan_phone(number, raw=True)
    assert isinstance(result_raw, dict)
    assert result_raw.get("valid") is True
    assert result_raw.get("country_code") == 44


def test_phone_invalid_number() -> None:
    """Test phone module with an invalid phone number."""
    number = "this-is-not-a-number"
    result_text = scan_phone(number, raw=False)
    assert isinstance(result_text, str)
    assert "Failed to parse" in result_text or "Invalid" in result_text or "[!]" in result_text

    result_raw = scan_phone(number, raw=True)
    assert isinstance(result_raw, dict)
    assert "error" in result_raw


def test_phone_empty_input() -> None:
    """Test phone module when empty string is provided."""
    result_text = scan_phone("", raw=False)
    assert isinstance(result_text, str)
    assert "[!]" in result_text

    result_raw = scan_phone("", raw=True)
    assert isinstance(result_raw, dict)
    assert "error" in result_raw


# =========================================================================
# 2. IP MODULE TESTS (Mocked HTTP - No Network)
# =========================================================================

@mock.patch("requests.get")
def test_ip_scan_success(mock_get: mock.MagicMock) -> None:
    """Test IP scan with a mocked successful ip-api.com response."""
    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "regionName": "Virginia",
        "city": "Ashburn",
        "zip": "20149",
        "lat": 39.0438,
        "lon": -77.4874,
        "timezone": "America/New_York",
        "isp": "Google LLC",
        "org": "Google Public DNS",
        "as": "AS15169 Google LLC",
        "query": "8.8.8.8",
        "proxy": True,
        "hosting": True,
        "mobile": False,
    }
    mock_get.return_value = mock_resp

    result_text = scan_ip("8.8.8.8", raw=False)
    assert isinstance(result_text, str)
    assert "United States (US)" in result_text
    assert "Ashburn" in result_text
    assert "Google LLC" in result_text
    assert "Proxy / VPN:" in result_text
    assert "Hosting / Cloud:" in result_text

    result_raw = scan_ip("8.8.8.8", raw=True)
    assert isinstance(result_raw, dict)
    assert result_raw.get("status") == "success"
    assert result_raw.get("proxy") is True
    assert result_raw.get("hosting") is True


@mock.patch("requests.get")
def test_ip_scan_failed_query(mock_get: mock.MagicMock) -> None:
    """Test IP scan with a mocked failure response."""
    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "fail",
        "message": "invalid query",
        "query": "999.999.999.999",
    }
    mock_get.return_value = mock_resp

    result_text = scan_ip("999.999.999.999", raw=False)
    assert isinstance(result_text, str)
    assert "invalid query" in result_text

    result_raw = scan_ip("999.999.999.999", raw=True)
    assert isinstance(result_raw, dict)
    assert "error" in result_raw


@mock.patch("requests.get")
def test_ip_scan_exception(mock_get: mock.MagicMock) -> None:
    """Test IP scan when requests raises a network exception."""
    import requests
    mock_get.side_effect = requests.RequestException("DNS lookup timeout")

    result_text = scan_ip("1.1.1.1", raw=False)
    assert isinstance(result_text, str)
    assert "DNS lookup timeout" in result_text

    result_raw = scan_ip("1.1.1.1", raw=True)
    assert isinstance(result_raw, dict)
    assert "error" in result_raw


def test_ip_scan_empty_input() -> None:
    """Test IP scan with empty input string."""
    result_text = scan_ip("", raw=False)
    assert isinstance(result_text, str)
    assert "[!]" in result_text


# =========================================================================
# 3. BREACH MODULE TESTS (Mocked HTTP - No Network)
# =========================================================================

def test_breach_missing_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test breach scan when HIBP_API_KEY environment variable is absent."""
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    result = scan_breaches("test@example.com", raw=False)
    assert isinstance(result, str)
    assert "HIBP_API_KEY" in result
    assert "https://haveibeenpwned.com/API/Key" in result


@mock.patch("requests.get")
def test_breach_404_no_breaches(mock_get: mock.MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test breach scan when account has no breaches (HTTP 404)."""
    monkeypatch.setenv("HIBP_API_KEY", "dummy_test_key")
    mock_resp = mock.MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp

    result = scan_breaches("clean@example.com", raw=False)
    assert isinstance(result, str)
    assert "No breaches found" in result


@mock.patch("requests.get")
def test_breach_200_found_breaches(mock_get: mock.MagicMock, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test breach scan when account is compromised (HTTP 200)."""
    monkeypatch.setenv("HIBP_API_KEY", "dummy_test_key")
    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = [
        {
            "Name": "Adobe",
            "BreachDate": "2013-10-04",
            "DataClasses": ["Email addresses", "Passwords", "Password hints"],
        },
        {
            "Name": "Canva",
            "BreachDate": "2019-05-24",
            "DataClasses": ["Email addresses", "Names", "Passwords"],
        },
    ]
    mock_get.return_value = mock_resp

    result = scan_breaches("victim@example.com", raw=False)
    assert isinstance(result, str)
    assert "Adobe" in result
    assert "2013-10-04" in result
    assert "Passwords" in result
    assert "Canva" in result


# =========================================================================
# 4. SOCIAL MODULE TESTS (Mocked HTTP - No Network)
# =========================================================================

@mock.patch("requests.get")
def test_social_gravatar_found(mock_get: mock.MagicMock) -> None:
    """Test social module Gravatar lookup when profile exists."""
    def _mock_side_effect(url, **kwargs):
        m = mock.MagicMock()
        if "/avatar/" in url:
            m.status_code = 200
        elif ".json" in url:
            m.status_code = 200
            m.json.return_value = {
                "entry": [
                    {
                        "displayName": "Alex Investigator",
                        "preferredUsername": "alexinv",
                        "aboutMe": "Security Enthusiast",
                        "currentLocation": "New York",
                    }
                ]
            }
        else:
            m.status_code = 404
        return m

    mock_get.side_effect = _mock_side_effect

    result = scan_social("alex@example.com", raw=False)
    assert isinstance(result, str)
    assert "Gravatar Profile Detected" in result
    assert "Alex Investigator" in result
    assert "alexinv" in result


# =========================================================================
# 5. CORE & REPORT TESTS
# =========================================================================

def test_strip_ansi_colors() -> None:
    """Verify that ANSI color codes are stripped cleanly."""
    colored_str = f"{colors.Fore.GREEN}Success{colors.Style.RESET_ALL} test"
    clean = colors.strip_ansi(colored_str)
    assert clean == "Success test"
    assert "\x1b" not in clean


def test_spinner_context_manager() -> None:
    """Verify spinner context manager runs and exits without error."""
    with Spinner("Testing spinner", delay=0.01, enabled=True) as sp:
        assert sp.enabled is True
    # Spinner is successfully stopped


def test_save_report_txt_and_json(tmp_path) -> None:
    """Verify saving reports to .txt and .json files."""
    json_path = str(tmp_path / "test_report.json")
    txt_path = str(tmp_path / "test_report.txt")

    data = {"sample_key": "sample_value"}
    text = "KaraQargha Report Content"

    # Save JSON
    status_json = save_report(json_path, data, text)
    assert "successfully saved to JSON" in status_json
    assert os.path.exists(json_path)
    with open(json_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
        assert loaded.get("sample_key") == "sample_value"

    # Save TXT
    status_txt = save_report(txt_path, data, text)
    assert "successfully saved to text file" in status_txt
    assert os.path.exists(txt_path)
    with open(txt_path, "r", encoding="utf-8") as f:
        content = f.read()
        assert "KaraQargha Report Content" in content


def test_argparse_flags() -> None:
    """Test CLI argument parser flags."""
    parser = build_parser()
    args = parser.parse_args(["-e", "test@mail.com", "-p", "+14155552671", "--json", "-o", "out.json"])
    assert args.email == "test@mail.com"
    assert args.phone == "+14155552671"
    assert args.json is True
    assert args.output == "out.json"

    args_all = parser.parse_args(["-a", "someone@domain.com"])
    assert args_all.all_target == "someone@domain.com"
