"""HTML report generator — self-contained visual report with no external dependencies."""

import html
import os
from urllib.parse import urlparse

from sqli_recon.models import ParamLocation


def generate_html_report(findings, output_dir, tech_summary=None, sqlmap_notes=None, stats=None):
    """Generate a self-contained HTML report."""
    path = os.path.join(output_dir, "report.html")

    high = sum(1 for f in findings if f.risk_level == "HIGH")
    medium = sum(1 for f in findings if f.risk_level == "MEDIUM")
    low = sum(1 for f in findings if f.risk_level == "LOW")

    rows = []
    for i, f in enumerate(findings):
        ep = f.endpoint
        p = f.parameter
        risk_class = f.risk_level.lower()
        reasons_html = "<br>".join(html.escape(r) for r in f.reasons)
        path_display = urlparse(ep.url).path or "/"

        rows.append(f"""
        <tr class="{risk_class}">
            <td>{f.score:.2f}</td>
            <td><span class="badge {risk_class}">{f.risk_level}</span></td>
            <td>{html.escape(ep.method)}</td>
            <td title="{html.escape(ep.url)}">{html.escape(path_display)}</td>
            <td><strong>{html.escape(p.name)}</strong></td>
            <td>{html.escape(p.location.value)}</td>
            <td>{html.escape(ep.source.value)}</td>
            <td class="reasons">{reasons_html}</td>
        </tr>""")

    tech_section = ""
    if tech_summary:
        tech_items = "".join(f"<li>{html.escape(t)}: {c:.0%}</li>" for t, c in tech_summary)
        tech_section = f"""
        <div class="card">
            <h2>Technology Stack</h2>
            <ul>{tech_items}</ul>
        </div>"""

    notes_section = ""
    if sqlmap_notes:
        notes_items = "".join(f"<li>{html.escape(n)}</li>" for n in sqlmap_notes)
        notes_section = f"""
        <div class="card">
            <h2>sqlmap Optimization</h2>
            <ul>{notes_items}</ul>
        </div>"""

    stats_section = ""
    if stats:
        stats_section = f"""
        <div class="card">
            <h2>Scan Statistics</h2>
            <table class="stats">
                <tr><td>Requests</td><td>{stats.get('requests', 0)}</td></tr>
                <tr><td>Successful</td><td>{stats.get('success', 0)}</td></tr>
                <tr><td>WAF Blocks</td><td>{stats.get('waf_blocks', 0)}</td></tr>
                <tr><td>Rate Limited</td><td>{stats.get('rate_limited', 0)}</td></tr>
                <tr><td>CAPTCHAs</td><td>{stats.get('captchas', 0)}</td></tr>
                <tr><td>Errors</td><td>{stats.get('errors', 0)}</td></tr>
            </table>
        </div>"""

    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>sqli_recon Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
           background: #0d1117; color: #c9d1d9; padding: 20px; }}
    h1 {{ color: #58a6ff; margin-bottom: 5px; }}
    h2 {{ color: #8b949e; font-size: 1.1em; margin-bottom: 10px; }}
    .header {{ margin-bottom: 30px; }}
    .summary {{ display: flex; gap: 15px; margin: 15px 0; }}
    .summary .box {{ padding: 15px 25px; border-radius: 8px; text-align: center; }}
    .summary .box.high {{ background: #3d1a1a; border: 1px solid #f85149; }}
    .summary .box.medium {{ background: #3d2e1a; border: 1px solid #d29922; }}
    .summary .box.low {{ background: #1a2d1a; border: 1px solid #3fb950; }}
    .summary .box .count {{ font-size: 2em; font-weight: bold; }}
    .summary .box.high .count {{ color: #f85149; }}
    .summary .box.medium .count {{ color: #d29922; }}
    .summary .box.low .count {{ color: #3fb950; }}
    .summary .box .label {{ font-size: 0.85em; color: #8b949e; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
             padding: 20px; margin-bottom: 20px; }}
    .card ul {{ padding-left: 20px; }}
    .card li {{ margin: 4px 0; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
    th {{ background: #21262d; color: #8b949e; text-align: left; padding: 10px 8px;
          font-size: 0.85em; text-transform: uppercase; border-bottom: 2px solid #30363d; }}
    td {{ padding: 8px; border-bottom: 1px solid #21262d; font-size: 0.9em; }}
    tr:hover {{ background: #161b22; }}
    tr.high td {{ border-left: 3px solid #f85149; }}
    tr.medium td:first-child {{ border-left: 3px solid #d29922; }}
    tr.low td:first-child {{ border-left: 3px solid #3fb950; }}
    .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
    .badge.high {{ background: #3d1a1a; color: #f85149; }}
    .badge.medium {{ background: #3d2e1a; color: #d29922; }}
    .badge.low {{ background: #1a2d1a; color: #3fb950; }}
    .reasons {{ font-size: 0.8em; color: #8b949e; max-width: 300px; }}
    .stats td {{ padding: 5px 10px; }}
    .stats td:last-child {{ text-align: right; font-weight: bold; }}
    .footer {{ margin-top: 30px; padding-top: 15px; border-top: 1px solid #21262d;
               color: #484f58; font-size: 0.85em; }}
</style>
</head>
<body>

<div class="header">
    <h1>sqli_recon Report</h1>
    <h2>SQL Injection Surface Discovery</h2>
</div>

<div class="summary">
    <div class="box high"><div class="count">{high}</div><div class="label">HIGH</div></div>
    <div class="box medium"><div class="count">{medium}</div><div class="label">MEDIUM</div></div>
    <div class="box low"><div class="count">{low}</div><div class="label">LOW</div></div>
</div>

{tech_section}
{notes_section}
{stats_section}

<div class="card">
    <h2>Findings ({len(findings)} total)</h2>
    <table>
        <thead>
            <tr>
                <th>Score</th>
                <th>Risk</th>
                <th>Method</th>
                <th>Endpoint</th>
                <th>Parameter</th>
                <th>Location</th>
                <th>Source</th>
                <th>Reasons</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows)}
        </tbody>
    </table>
</div>

<div class="footer">
    Generated by sqli_recon &mdash; SQL Injection Surface Discovery Tool
</div>

</body>
</html>"""

    with open(path, "w") as f:
        f.write(report_html)

    return path
