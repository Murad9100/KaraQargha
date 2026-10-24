"""Tests for new KaraQargha modules (mocked network)."""

from unittest import mock

from karagargha.modules.crypto import scan_crypto


@mock.patch("requests.get")
def test_crypto_scan(mock_get):
    mock_resp = mock.MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "chain_stats": {
            "funded_txo_count": 1,
            "spent_txo_count": 0,
            "tx_count": 1,
            "funded_sat": 5000,
            "spent_sat": 0,
        },
        "mempool_stats": {"tx_count": 0},
    }
    mock_get.return_value = mock_resp

    txt = scan_crypto("bc1qexample", raw=False)
    assert isinstance(txt, str)
    assert "Balance (sat): 5000" in txt

    raw = scan_crypto("bc1qexample", raw=True)
    assert raw.get("balance_sat") == 5000


def test_email_header_parser(tmp_path):
    from karagargha.modules.email import scan_email_headers

    p = tmp_path / "headers.txt"
    p.write_text(
        "From: a@example.com\nTo: b@example.com\nSubject: Hi\nDate: Mon, 1 Jan 2024 00:00:00 +0000\nReceived: from mail.example.com (192.0.2.1)\nReceived-SPF: pass\nAuthentication-Results: spf=pass; dkim=pass\nDKIM-Signature: v=1\n",
        encoding="utf-8",
    )
    res = scan_email_headers(str(p), raw=False)
    assert "Originating IP: 192.0.2.1" in res
    assert "DKIM present: Yes" in res


def test_image_missing_file():
    from karagargha.modules.image import scan_image
    res = scan_image("/no/such/file.jpg", raw=False)
    assert "[!]" in res
