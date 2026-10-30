"""Output: turn the scan's results into the three files.

- JSON: everything, including each certificate in PEM. Its layout is fixed
  and versioned (`FORMAT_VERSION`), so other tools can read it.
- CSV: one row per endpoint, for a spreadsheet.
- HTML: one self-contained page to read in a browser (no internet needed:
  styles and script are inside it, and its security policy blocks anything else).

All three are built from the same "document" (`document()`), so they always
agree. Nothing here touches the network.
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime
from typing import Any

from certavert_scan import FORMAT_VERSION, __version__


# Sort order: what needs attention first.
STATUS_ORDER = {"Expired": 0, "Error": 1, "Not yet valid": 2, "Expiring": 3, "OK": 4}

# The CSV's header row, in order.
CSV_COLUMNS = [
    "Status",
    "Days left",
    "Endpoint",
    "Address",
    "Port",
    "Name",
    "Reverse DNS",
    "Common name",
    "SANs",
    "Issuer",
    "Self-signed",
    "Not before",
    "Not after",
    "TLS version",
    "Cipher",
    "Key",
    "Signature",
    "Serial",
    "SHA-256",
    "Issues",
    "Error",
]


def sort_key(result: dict[str, Any]) -> tuple:
    """Status first, then fewest days left, then address and port."""
    cert = result.get("certificate") or {}
    days = cert.get("days_left")
    return (
        STATUS_ORDER.get(result["status"], 9),
        days if days is not None else 10**9,
        result["address"],
        result["port"],
    )


def summary(results: list[dict[str, Any]]) -> dict[str, int]:
    """Counts for the top of the page: endpoints, unique certificates, and each status.

    One wildcard certificate on 20 servers is 20 endpoints but 1 certificate
    (counted by its SHA-256 fingerprint).
    """
    counts = {"endpoints": len(results), "certificates": 0}
    for status in STATUS_ORDER:
        counts[status] = 0
    fingerprints = set()
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
        if result.get("certificate"):
            fingerprints.add(result["certificate"]["sha256"])
    counts["certificates"] = len(fingerprints)
    return counts


def document(results: list[dict[str, Any]], scan: dict[str, Any]) -> dict[str, Any]:
    """The whole scan as one dict: this is exactly what the JSON file holds."""
    results = sorted(results, key=sort_key)
    return {
        "format": "certavert-scan",
        "format_version": FORMAT_VERSION,
        "tool_version": __version__,
        "scan": scan,
        "summary": summary(results),
        "endpoints": results,
    }


def to_json(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _cell(value: Any) -> str:
    """One CSV cell. Certificate fields are written by whoever made the certificate,
    so a value that a spreadsheet would run as a formula gets a leading "'"."""
    text = "" if value is None else str(value)
    # A cell starting with these is run as a formula by spreadsheets.
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        text = "'" + text
    return text


def _key_text(cert: dict[str, Any]) -> str:
    """The key as shown: "RSA 2048", "EC P-256", "Ed25519"."""
    if cert.get("key_bits") and not cert["key_type"].startswith(("Ed", "EC")):
        return f"{cert['key_type']} {cert['key_bits']}"
    return cert.get("key_type") or ""


def to_csv(doc: dict[str, Any]) -> str:
    """One row per endpoint, columns as in CSV_COLUMNS."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    for r in doc["endpoints"]:
        c = r.get("certificate") or {}
        row = [
            r["status"],
            c.get("days_left"),
            r["endpoint"],
            r["address"],
            r["port"],
            r.get("name"),
            r.get("reverse_dns"),
            c.get("common_name"),
            " ".join(c.get("sans") or []),
            c.get("issuer"),
            ("Yes" if c.get("self_signed") else "No") if c else "",
            c.get("not_before"),
            c.get("not_after"),
            r.get("tls_version"),
            r.get("cipher"),
            _key_text(c) if c else "",
            c.get("signature"),
            c.get("serial"),
            c.get("sha256"),
            "; ".join(r.get("issues") or []),
            r.get("error"),
        ]
        writer.writerow([_cell(v) for v in row])
    # UTF-8 with BOM so Excel reads names with accents correctly.
    return "﻿" + buffer.getvalue()


def _short_date(iso: str | None) -> str:
    """"2026-12-07T02:20:16Z" as "Dec 7, 2026"."""
    if not iso:
        return ""
    moment = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    return f"{moment:%b} {moment.day}, {moment.year}"


def _e(value: Any) -> str:
    """Escape for HTML. Every value from a certificate goes through this: a
    certificate named "<script>" must show as text, never run."""
    return html.escape("" if value is None else str(value), quote=True)


# Status to colour (the CSS classes below).
STATUS_CLASS = {
    "OK": "ok",
    "Expiring": "expiring",
    "Expired": "expired",
    "Error": "error",
    "Not yet valid": "expiring",
}

# The page's styles: light and dark (follows the computer's setting), works on a phone.
CSS = """
:root{--bg:#f8fafc;--card:#fff;--text:#0f172a;--muted:#64748b;--line:#e2e8f0;--head:#f1f5f9;
--ok:#15803d;--ok-bg:#dcfce7;--warn:#c2410c;--warn-bg:#ffedd5;--bad:#b91c1c;--bad-bg:#fee2e2;--link:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#0b1120;--card:#111827;--text:#e5e7eb;--muted:#94a3b8;--line:#1f2937;
--head:#0f172a;--ok:#4ade80;--ok-bg:#052e16;--warn:#fb923c;--warn-bg:#431407;--bad:#f87171;--bad-bg:#450a0a;--link:#60a5fa}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1536px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:20px;margin:0 0 4px}
.meta{color:var(--muted);margin:0 0 16px}
.counts{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 16px;padding:0;list-style:none}
.counts li{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px}
.counts b{font-size:18px;margin-right:4px}
.tools{margin:0 0 12px}
.tools input{width:100%;max-width:360px;padding:8px 10px;border:1px solid var(--line);border-radius:8px;
background:var(--card);color:var(--text);font:inherit}
.wrap{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}
table{border-collapse:collapse;width:100%}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:var(--head);font-weight:600;white-space:nowrap;cursor:pointer;user-select:none;position:sticky;top:0}
tr:last-child td{border-bottom:0}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.nowrap{white-space:nowrap}
.muted{color:var(--muted)}
.pill{display:inline-block;padding:1px 8px;border-radius:999px;font-weight:600;font-size:12px;white-space:nowrap}
.ok{color:var(--ok);background:var(--ok-bg)}.expiring{color:var(--warn);background:var(--warn-bg)}
.expired,.error{color:var(--bad);background:var(--bad-bg)}
.sans{max-width:320px;word-break:break-all}
details summary{cursor:pointer;color:var(--link)}
footer{margin-top:24px;color:var(--muted)}
footer a{color:var(--link)}
"""

# The page's only script: the Filter box, and sorting by clicking a column header.
JS = """
(function(){
var input=document.getElementById('filter'),rows=[].slice.call(document.querySelectorAll('tbody tr'));
input.addEventListener('input',function(){var q=input.value.toLowerCase();
rows.forEach(function(r){r.hidden=q&&r.textContent.toLowerCase().indexOf(q)<0;});});
[].forEach.call(document.querySelectorAll('th'),function(th,i){var asc=true;th.addEventListener('click',function(){
var body=document.querySelector('tbody');rows.sort(function(a,b){
var x=a.children[i].dataset.sort||a.children[i].textContent,y=b.children[i].dataset.sort||b.children[i].textContent;
var nx=parseFloat(x),ny=parseFloat(y);var c=(!isNaN(nx)&&!isNaN(ny))?nx-ny:x.localeCompare(y);return asc?c:-c;});
asc=!asc;rows.forEach(function(r){body.appendChild(r);});});});
})();
"""


def _row(index: int, r: dict[str, Any]) -> str:
    """One table row. `index` keeps the original order when sorting by Status."""
    c = r.get("certificate") or {}
    name = r.get("name") or r.get("reverse_dns")
    endpoint = f'<span class="nowrap">{_e(r["endpoint"])}</span>'
    if name and r.get("name") is None:
        endpoint += f'<br><span class="muted">{_e(name)}</span>'
    elif r.get("name"):
        endpoint += f'<br><span class="muted">{_e(r["address"])}</span>'
    status = f'<span class="pill {STATUS_CLASS.get(r["status"], "error")}">{_e(r["status"])}</span>'
    if not c:
        return (
            f'<tr><td data-sort="{index}">{status}</td><td class="num" data-sort="999999"></td><td>{endpoint}</td>'
            f'<td colspan="6" class="muted">{_e(r.get("error"))}</td></tr>'
        )
    sans = c.get("sans") or []
    sans_html = _e(", ".join(sans[:3]))
    if len(sans) > 3:
        sans_html = (
            f"<details><summary>{_e(', '.join(sans[:3]))} +{len(sans) - 3}</summary>"
            f"{_e(', '.join(sans[3:]))}</details>"
        )
    issuer = _e(c.get("issuer_common_name") or c.get("issuer_organization") or c.get("issuer"))
    if c.get("self_signed"):
        issuer += ' <span class="muted">(self-signed)</span>'
    elif c.get("issuer_common_name") and c.get("issuer_organization"):
        issuer += f'<br><span class="muted">{_e(c["issuer_organization"])}</span>'
    return (
        f'<tr><td data-sort="{index}">{status}</td>'
        f'<td class="num" data-sort="{c["days_left"]}">{_e(c["days_left"])}</td>'
        f"<td>{endpoint}</td>"
        f'<td>{_e(c.get("common_name"))}<div class="sans muted">{sans_html}</div></td>'
        f'<td title="{_e(c.get("issuer"))}">{issuer}</td>'
        f'<td class="nowrap" data-sort="{_e(c["not_after"])}">{_e(_short_date(c["not_after"]))}</td>'
        f'<td class="nowrap">{_e(r.get("tls_version"))}</td>'
        f'<td class="nowrap">{_e(_key_text(c))}</td>'
        f'<td>{_e(", ".join(r.get("issues") or []))}</td></tr>'
    )


def to_html(doc: dict[str, Any]) -> str:
    """The whole page: title, scan details, counts, Filter box, table, footer."""
    s = doc["summary"]
    scan = doc["scan"]
    counts = [("Endpoints", s["endpoints"]), ("Certificates", s["certificates"])]
    counts += [(label, s[label]) for label in ("Expired", "Expiring", "OK", "Error") if s.get(label)]
    if s.get("Not yet valid"):
        counts.append(("Not yet valid", s["Not yet valid"]))
    counts_html = "".join(f"<li><b>{_e(n)}</b>{_e(label)}</li>" for label, n in counts)
    rows = "".join(_row(i, r) for i, r in enumerate(doc["endpoints"]))
    if not rows:
        rows = '<tr><td colspan="9" class="muted">No TLS endpoints found.</td></tr>'
    meta = (
        f"{_e(_short_date(scan['finished_at']))} · {_e(scan['targets_text'])} · ports {_e(scan['ports_text'])}"
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Certificates found</title>
<style>{CSS}</style>
</head>
<body>
<main>
<h1>Certificates found</h1>
<p class="meta">{meta}</p>
<ul class="counts">{counts_html}</ul>
<div class="tools"><input id="filter" type="search" placeholder="Filter" aria-label="Filter"></div>
<div class="wrap">
<table>
<thead><tr><th>Status</th><th>Days left</th><th>Endpoint</th><th>Name</th><th>Issuer</th><th>Expires</th><th>TLS</th><th>Key</th><th>Issues</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
<footer>certavert-scan {_e(doc["tool_version"])} · Expiry alerts for your public certificates: <a href="https://certavert.com" rel="noopener">certavert.com</a></footer>
</main>
<script>{JS}</script>
</body>
</html>
"""
