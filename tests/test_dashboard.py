"""Tests for the self-contained dashboard generation (cli/e2e.py --dashboard)."""

import json
import re

from cli.e2e import _write_dashboard

_DEMO_DATA = {
    "overall": "PASS",
    "pipeline": [{"stage": "capture", "ok": True, "detail": "42 bytes"}],
    "capture": {"source": "thermal", "sample_rate": 48000.0,
                "seconds": 1.0, "bytes": 42},
    "entropy": {"shannon_bits_per_byte": 7.0, "nist90b_bits_per_byte": 6.0,
                "conservative_min_bits_per_byte": 6.0,
                "truth_bits_per_byte": 7.05},
    "hardening": {"degree": 31, "evaluations": 64,
                  "poly_points": [1, 2, 3], "mac": "aa"},
    "identity": {"node_id": "n1", "window_id": "w1", "nullifier": "ff"},
    "certificate": {"version": 1, "body_bytes": 100, "mac_b64": "zz"},
    "transport": {"route": ["a", "b", "c"], "onion_bytes": 500,
                  "rs": {"k": 2, "n": 4}, "shards": 4,
                  "dtn_delivered": 4, "dtn_dropped": 0},
    "matching": {"bids": 1, "offers": 2, "crossed": 1, "total_quantity": 1},
    "settlement": {"price": 100, "payee": "payee-node",
                   "payee_balance": 100, "spent_count": 1},
}


def _render(tmp_path, data=None):
    out = tmp_path / "dashboard.html"
    _write_dashboard(str(out), data or _DEMO_DATA)
    return out.read_text(encoding="utf-8")


def test_dashboard_is_deterministic(tmp_path):
    assert _render(tmp_path) == _render(tmp_path)


def test_dashboard_embeds_valid_json(tmp_path):
    html = _render(tmp_path)
    m = re.search(r'<script type="application/json" id="pem-data">\s*(.*?)\s*</script>',
                  html, re.S)
    assert m, "inline JSON script tag missing"
    embedded = json.loads(m.group(1))
    assert embedded["overall"] == "PASS"
    assert embedded["capture"]["bytes"] == 42
    assert embedded["transport"]["rs"] == {"k": 2, "n": 4}


def test_dashboard_has_no_template_placeholder(tmp_path):
    html = _render(tmp_path)
    assert "__PEM_DATA_JSON__" not in html
    assert 'id="pem-data"' in html


def test_dashboard_contains_all_sections(tmp_path):
    html = _render(tmp_path)
    for section in ("pipeline", "capture", "entropy-bars", "hardening",
                    "identity", "certificate", "transport", "match-settle",
                    "raw"):
        assert f'id="{section}"' in html
    assert "function render(d)" in html


def test_dashboard_script_tag_escaping(tmp_path):
    """JSON containing a script tag must not break the inline JSON block."""
    data = {"overall": "PASS", "note": "</script><script>alert(1)</script>"}
    html = _render(tmp_path, data)
    block = html.split('<script type="application/json" id="pem-data">')[1]
    assert "</script><script>" not in block
    m = re.search(r'id="pem-data">\s*(.*?)\s*</script>', html, re.S)
    assert m
    assert json.loads(m.group(1))["note"] == "</script><script>alert(1)</script>"