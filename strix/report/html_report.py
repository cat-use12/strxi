"""Interactive HTML report generator for Strix scan results.

Generates a self-contained single-file HTML report with:
  - Summary dashboard (severity counts, risk score)
  - Filterable/sortable findings table
  - Finding detail modals
  - No external dependencies — works offline

Usage::
    from strix.report.html_report import generate_html_report, write_html_report
    html = generate_html_report(vulnerabilities, target="https://example.com")
    write_html_report("report.html", vulnerabilities, target="https://example.com")
"""

from __future__ import annotations

import html as html_lib
import json
import logging
from datetime import datetime, UTC
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
_SEVERITY_COLORS = {
    "critical": "#e53e3e",
    "high":     "#dd6b20",
    "medium":   "#d69e2e",
    "low":      "#38a169",
    "info":     "#3182ce",
    "unknown":  "#718096",
}
_SEVERITY_BG = {
    "critical": "#fff5f5",
    "high":     "#fffaf0",
    "medium":   "#fffff0",
    "low":      "#f0fff4",
    "info":     "#ebf8ff",
    "unknown":  "#f7fafc",
}


def _esc(s: str) -> str:
    return html_lib.escape(str(s or ""), quote=True)


def _sev(f: dict[str, Any]) -> str:
    return str(f.get("severity") or "unknown").lower()


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(findings, key=lambda f: _SEVERITY_ORDER.get(_sev(f), 5))


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {k: 0 for k in _SEVERITY_ORDER}
    for f in findings:
        s = _sev(f)
        counts[s] = counts.get(s, 0) + 1
    return counts


def _risk_score(counts: dict[str, int]) -> int:
    """Simple weighted risk score 0–100."""
    weights = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0, "unknown": 1}
    raw = sum(counts.get(k, 0) * w for k, w in weights.items())
    return min(100, raw)


def _risk_label(score: int) -> tuple[str, str]:
    if score >= 80:
        return "CRITICAL RISK", "#e53e3e"
    if score >= 50:
        return "HIGH RISK", "#dd6b20"
    if score >= 20:
        return "MEDIUM RISK", "#d69e2e"
    if score > 0:
        return "LOW RISK", "#38a169"
    return "NO FINDINGS", "#718096"


# ─── HTML generation ──────────────────────────────────────────────────────────

def generate_html_report(
    vulnerabilities: list[dict[str, Any]],
    *,
    target: str = "",
    scan_id: str = "",
    title: str = "Strix Security Scan Report",
) -> str:
    """Generate a self-contained HTML security report."""
    findings = _sort_findings(vulnerabilities)
    counts = _count_by_severity(findings)
    score = _risk_score(counts)
    risk_label, risk_color = _risk_label(score)
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    # Serialize findings for JavaScript
    findings_json = json.dumps([
        {
            "id": i,
            "title": f.get("title") or f.get("name") or "Unknown",
            "severity": _sev(f),
            "endpoint": str(f.get("endpoint") or f.get("url") or ""),
            "description": str(f.get("description") or "")[:500],
            "remediation": str(f.get("remediation") or f.get("recommendation") or ""),
            "cve": str(f.get("cve") or ""),
            "cwe": str(f.get("cwe") or ""),
            "cvss": str(f.get("cvss") or f.get("cvss_score") or ""),
            "references": f.get("references") or [],
            "evidence": str(f.get("evidence") or f.get("payload") or "")[:300],
        }
        for i, f in enumerate(findings)
    ], ensure_ascii=False)

    severity_badges_html = "".join(
        f'<span class="badge" style="background:{_SEVERITY_COLORS.get(k, "#718096")}">'
        f'{counts.get(k, 0)} {k.upper()}</span>'
        for k in ("critical", "high", "medium", "low", "info")
        if counts.get(k, 0) > 0
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(title)}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  :root {{
    --bg: #f8f9fa; --card: #ffffff; --border: #e2e8f0; --text: #1a202c;
    --text-muted: #718096; --accent: #4a5568;
  }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 24px 16px; }}
  .header {{ background: #1a202c; color: #fff; padding: 32px 24px; border-radius: 12px; margin-bottom: 24px; }}
  .header h1 {{ font-size: 1.8rem; font-weight: 700; margin-bottom: 8px; }}
  .header .meta {{ color: #a0aec0; font-size: 0.9rem; }}
  .header .meta span {{ margin-right: 20px; }}
  .risk-banner {{ display: flex; align-items: center; gap: 16px; margin-top: 16px;
    background: rgba(255,255,255,0.1); border-radius: 8px; padding: 12px 16px; }}
  .risk-score {{ font-size: 2rem; font-weight: 800; }}
  .risk-label {{ font-size: 1rem; font-weight: 600; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .card {{ background: var(--card); border-radius: 10px; border: 1px solid var(--border);
    padding: 20px 16px; text-align: center; }}
  .card .count {{ font-size: 2.2rem; font-weight: 800; }}
  .card .label {{ font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em;
    color: var(--text-muted); margin-top: 4px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem;
    font-weight: 600; color: #fff; margin: 0 2px; }}
  .filters {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px;
    padding: 16px; margin-bottom: 16px; display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }}
  .filters input {{ flex: 1; min-width: 200px; padding: 8px 12px; border: 1px solid var(--border);
    border-radius: 6px; font-size: 0.9rem; outline: none; }}
  .filters input:focus {{ border-color: #4a5568; }}
  .filter-btn {{ padding: 6px 14px; border-radius: 20px; border: 2px solid var(--border);
    background: var(--card); cursor: pointer; font-size: 0.82rem; font-weight: 600; transition: all 0.15s; }}
  .filter-btn:hover, .filter-btn.active {{ border-color: #4a5568; background: #4a5568; color: #fff; }}
  .filter-btn.sev-critical.active {{ border-color: #e53e3e; background: #e53e3e; }}
  .filter-btn.sev-high.active {{ border-color: #dd6b20; background: #dd6b20; }}
  .filter-btn.sev-medium.active {{ border-color: #d69e2e; background: #d69e2e; }}
  .filter-btn.sev-low.active {{ border-color: #38a169; background: #38a169; }}
  .filter-btn.sev-info.active {{ border-color: #3182ce; background: #3182ce; }}
  .table-wrap {{ background: var(--card); border: 1px solid var(--border); border-radius: 10px; overflow: hidden; }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead {{ background: #f7fafc; }}
  th {{ padding: 12px 16px; text-align: left; font-size: 0.8rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.05em; color: var(--text-muted); cursor: pointer; user-select: none; white-space: nowrap; }}
  th:hover {{ color: var(--text); }}
  th .sort-arrow {{ opacity: 0.3; margin-left: 4px; }}
  th.sorted .sort-arrow {{ opacity: 1; }}
  td {{ padding: 12px 16px; border-top: 1px solid var(--border); vertical-align: top; }}
  tr:hover td {{ background: #f7fafc; }}
  .sev-pill {{ display: inline-block; padding: 2px 10px; border-radius: 20px; font-size: 0.75rem;
    font-weight: 700; color: #fff; text-transform: uppercase; }}
  .title-cell {{ font-weight: 500; max-width: 300px; word-break: break-word; }}
  .endpoint-cell {{ font-family: "Courier New", monospace; font-size: 0.8rem; color: var(--text-muted);
    max-width: 250px; word-break: break-all; }}
  .detail-btn {{ padding: 4px 10px; border: 1px solid var(--border); border-radius: 5px; background: none;
    cursor: pointer; font-size: 0.8rem; color: var(--text-muted); }}
  .detail-btn:hover {{ background: var(--bg); color: var(--text); }}
  .no-findings {{ text-align: center; padding: 48px; color: var(--text-muted); }}
  /* Modal */
  .modal-overlay {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.5);
    z-index: 1000; align-items: center; justify-content: center; padding: 16px; }}
  .modal-overlay.open {{ display: flex; }}
  .modal {{ background: var(--card); border-radius: 12px; max-width: 700px; width: 100%;
    max-height: 90vh; overflow-y: auto; padding: 28px; position: relative; }}
  .modal-close {{ position: absolute; top: 16px; right: 16px; background: none; border: none;
    font-size: 1.4rem; cursor: pointer; color: var(--text-muted); line-height: 1; }}
  .modal h2 {{ font-size: 1.2rem; margin-bottom: 12px; padding-right: 30px; }}
  .modal-section {{ margin-top: 16px; }}
  .modal-section h3 {{ font-size: 0.8rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: 0.05em; color: var(--text-muted); margin-bottom: 6px; }}
  .modal-section p, .modal-section pre {{ font-size: 0.9rem; }}
  .modal-section pre {{ background: #f7fafc; border: 1px solid var(--border); border-radius: 6px;
    padding: 10px; overflow-x: auto; font-size: 0.82rem; white-space: pre-wrap; word-break: break-all; }}
  .footer {{ text-align: center; margin-top: 32px; color: var(--text-muted); font-size: 0.82rem; }}
  @media (max-width: 640px) {{
    .header h1 {{ font-size: 1.3rem; }}
    .cards {{ grid-template-columns: repeat(3, 1fr); }}
    td, th {{ padding: 8px 10px; font-size: 0.82rem; }}
    .endpoint-cell {{ display: none; }}
  }}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>🛡️ {_esc(title)}</h1>
  <div class="meta">
    {'<span>🎯 Target: <strong>' + _esc(target) + '</strong></span>' if target else ''}
    {'<span>🆔 Scan ID: <strong>' + _esc(scan_id) + '</strong></span>' if scan_id else ''}
    <span>📅 Generated: <strong>{_esc(now)}</strong></span>
    <span>🔍 Total findings: <strong>{len(findings)}</strong></span>
  </div>
  <div class="risk-banner">
    <div class="risk-score" style="color:{risk_color}">{score}</div>
    <div>
      <div class="risk-label" style="color:{risk_color}">{risk_label}</div>
      <div style="color:#a0aec0;font-size:0.82rem;margin-top:2px">Risk Score /100 — {severity_badges_html}</div>
    </div>
  </div>
</div>

<div class="cards">
  <div class="card" style="border-top:3px solid {_SEVERITY_COLORS['critical']}">
    <div class="count" style="color:{_SEVERITY_COLORS['critical']}">{counts.get('critical', 0)}</div>
    <div class="label">Critical</div>
  </div>
  <div class="card" style="border-top:3px solid {_SEVERITY_COLORS['high']}">
    <div class="count" style="color:{_SEVERITY_COLORS['high']}">{counts.get('high', 0)}</div>
    <div class="label">High</div>
  </div>
  <div class="card" style="border-top:3px solid {_SEVERITY_COLORS['medium']}">
    <div class="count" style="color:{_SEVERITY_COLORS['medium']}">{counts.get('medium', 0)}</div>
    <div class="label">Medium</div>
  </div>
  <div class="card" style="border-top:3px solid {_SEVERITY_COLORS['low']}">
    <div class="count" style="color:{_SEVERITY_COLORS['low']}">{counts.get('low', 0)}</div>
    <div class="label">Low</div>
  </div>
  <div class="card" style="border-top:3px solid {_SEVERITY_COLORS['info']}">
    <div class="count" style="color:{_SEVERITY_COLORS['info']}">{counts.get('info', 0)}</div>
    <div class="label">Info</div>
  </div>
</div>

<div class="filters">
  <input type="text" id="searchBox" placeholder="🔍 Filter by title, endpoint, CVE..." oninput="applyFilters()">
  <button class="filter-btn active" data-sev="all" onclick="setSevFilter('all', this)">All</button>
  <button class="filter-btn sev-critical" data-sev="critical" onclick="setSevFilter('critical', this)">Critical</button>
  <button class="filter-btn sev-high" data-sev="high" onclick="setSevFilter('high', this)">High</button>
  <button class="filter-btn sev-medium" data-sev="medium" onclick="setSevFilter('medium', this)">Medium</button>
  <button class="filter-btn sev-low" data-sev="low" onclick="setSevFilter('low', this)">Low</button>
  <button class="filter-btn sev-info" data-sev="info" onclick="setSevFilter('info', this)">Info</button>
  <span id="resultCount" style="color:#718096;font-size:0.85rem;margin-left:auto"></span>
</div>

<div class="table-wrap">
  <table id="findingsTable">
    <thead>
      <tr>
        <th onclick="sortTable(0)" data-col="0">#<span class="sort-arrow">↕</span></th>
        <th onclick="sortTable(1)" data-col="1">Severity<span class="sort-arrow">↕</span></th>
        <th onclick="sortTable(2)" data-col="2">Title<span class="sort-arrow">↕</span></th>
        <th onclick="sortTable(3)" data-col="3">Endpoint<span class="sort-arrow">↕</span></th>
        <th>Details</th>
      </tr>
    </thead>
    <tbody id="findingsBody"></tbody>
  </table>
  <div id="noFindings" class="no-findings" style="display:none">No findings match the current filter.</div>
</div>

<div class="modal-overlay" id="modalOverlay" onclick="closeModal(event)">
  <div class="modal" id="modal">
    <button class="modal-close" onclick="closeModalDirect()">✕</button>
    <div id="modalContent"></div>
  </div>
</div>

<div class="footer">
  Generated by <strong>Strix</strong> — AI-Powered Penetration Testing Agent &nbsp;•&nbsp; {_esc(now)}
</div>

</div>

<script>
const FINDINGS = {findings_json};
const SEV_COLORS = {json.dumps(_SEVERITY_COLORS)};
const SEV_ORDER = {json.dumps(_SEVERITY_ORDER)};

let currentSev = 'all';
let sortCol = 0;
let sortAsc = true;

function sevPill(sev) {{
  const color = SEV_COLORS[sev] || '#718096';
  return `<span class="sev-pill" style="background:${{color}}">${{sev}}</span>`;
}}

function renderTable(data) {{
  const body = document.getElementById('findingsBody');
  const noF = document.getElementById('noFindings');
  if (!data.length) {{
    body.innerHTML = '';
    noF.style.display = '';
    document.getElementById('resultCount').textContent = '0 findings';
    return;
  }}
  noF.style.display = 'none';
  document.getElementById('resultCount').textContent = `${{data.length}} finding${{data.length !== 1 ? 's' : ''}}`;
  body.innerHTML = data.map((f, i) =>
    `<tr>
      <td>${{i + 1}}</td>
      <td>${{sevPill(f.severity)}}</td>
      <td class="title-cell">${{escHtml(f.title)}}</td>
      <td class="endpoint-cell">${{escHtml(f.endpoint)}}</td>
      <td><button class="detail-btn" onclick="showDetail(${{f.id}})">View</button></td>
    </tr>`
  ).join('');
}}

function escHtml(s) {{
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}}

function applyFilters() {{
  const q = document.getElementById('searchBox').value.toLowerCase();
  let data = FINDINGS;
  if (currentSev !== 'all') data = data.filter(f => f.severity === currentSev);
  if (q) data = data.filter(f =>
    f.title.toLowerCase().includes(q) ||
    f.endpoint.toLowerCase().includes(q) ||
    f.cve.toLowerCase().includes(q) ||
    f.description.toLowerCase().includes(q)
  );
  data = sortData(data);
  renderTable(data);
}}

function setSevFilter(sev, btn) {{
  currentSev = sev;
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  applyFilters();
}}

function sortData(data) {{
  const cols = ['id', 'severity', 'title', 'endpoint'];
  const key = cols[sortCol] || 'id';
  return [...data].sort((a, b) => {{
    let va = key === 'severity' ? (SEV_ORDER[a[key]] ?? 5) : String(a[key] || '').toLowerCase();
    let vb = key === 'severity' ? (SEV_ORDER[b[key]] ?? 5) : String(b[key] || '').toLowerCase();
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ? 1 : -1;
    return 0;
  }});
}}

function sortTable(col) {{
  if (sortCol === col) sortAsc = !sortAsc;
  else {{ sortCol = col; sortAsc = true; }}
  document.querySelectorAll('th').forEach((th, i) => {{
    th.classList.toggle('sorted', i === col);
    const arrow = th.querySelector('.sort-arrow');
    if (arrow && i === col) arrow.textContent = sortAsc ? '↑' : '↓';
    else if (arrow) arrow.textContent = '↕';
  }});
  applyFilters();
}}

function showDetail(id) {{
  const f = FINDINGS.find(x => x.id === id);
  if (!f) return;
  const color = SEV_COLORS[f.severity] || '#718096';
  let html = `<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:4px">
    ${{sevPill(f.severity)}}
    ${{f.cve ? `<code style="font-size:0.82rem;background:#f7fafc;padding:2px 6px;border-radius:4px">${{escHtml(f.cve)}}</code>` : ''}}
    ${{f.cvss ? `<span style="font-size:0.82rem;color:#718096">CVSS ${{escHtml(f.cvss)}}</span>` : ''}}
  </div>
  <h2>${{escHtml(f.title)}}</h2>`;
  if (f.endpoint) html += `<div class="modal-section"><h3>Endpoint</h3><pre>${{escHtml(f.endpoint)}}</pre></div>`;
  if (f.description) html += `<div class="modal-section"><h3>Description</h3><p>${{escHtml(f.description)}}</p></div>`;
  if (f.evidence) html += `<div class="modal-section"><h3>Evidence / Payload</h3><pre>${{escHtml(f.evidence)}}</pre></div>`;
  if (f.remediation) html += `<div class="modal-section"><h3>Remediation</h3><p>${{escHtml(f.remediation)}}</p></div>`;
  if (f.cwe) html += `<div class="modal-section"><h3>CWE</h3><p>${{escHtml(f.cwe)}}</p></div>`;
  if (f.references && f.references.length) {{
    const refs = f.references.map(r => `<li><a href="${{escHtml(r)}}" target="_blank" rel="noopener noreferrer">${{escHtml(r)}}</a></li>`).join('');
    html += `<div class="modal-section"><h3>References</h3><ul style="padding-left:18px;font-size:0.88rem">${{refs}}</ul></div>`;
  }}
  document.getElementById('modalContent').innerHTML = html;
  document.getElementById('modalOverlay').classList.add('open');
  document.body.style.overflow = 'hidden';
}}

function closeModal(e) {{
  if (e.target === document.getElementById('modalOverlay')) closeModalDirect();
}}
function closeModalDirect() {{
  document.getElementById('modalOverlay').classList.remove('open');
  document.body.style.overflow = '';
}}
document.addEventListener('keydown', e => {{ if (e.key === 'Escape') closeModalDirect(); }});

// Initial render
renderTable(FINDINGS);
</script>
</body>
</html>"""


def write_html_report(
    output_path: str | Path,
    vulnerabilities: list[dict[str, Any]],
    *,
    target: str = "",
    scan_id: str = "",
    title: str = "Strix Security Scan Report",
) -> Path:
    """Write the HTML report to a file."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    html = generate_html_report(vulnerabilities, target=target, scan_id=scan_id, title=title)
    output_path.write_text(html, encoding="utf-8")
    logger.info("HTML report written to %s (%d findings)", output_path, len(vulnerabilities))
    return output_path
