"""
Reporter - Generates scan reports in JSON, HTML, and terminal formats.
"""

import json
import datetime
from typing import List, Dict
from pathlib import Path


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_COLORS = {
    "Critical": "#c0392b",
    "High": "#e67e22",
    "Medium": "#f1c40f",
    "Low": "#2980b9",
    "Info": "#7f8c8d",
}
SEVERITY_BADGE = {
    "Critical": "\033[1;31m",  # Bold Red
    "High":     "\033[0;31m",  # Red
    "Medium":   "\033[0;33m",  # Yellow
    "Low":      "\033[0;34m",  # Blue
    "Info":     "\033[0;37m",  # Grey
}
RESET = "\033[0m"


def _sort_findings(findings: List[Dict]) -> List[Dict]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "Info"), 99))


# ── Terminal ──────────────────────────────────────────────────────────────────

def print_terminal(findings: List[Dict], target: str):
    findings = _sort_findings(findings)
    print(f"\n{'='*70}")
    print(f"  WebVulnScan Report — {target}")
    print(f"  {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*70}")

    if not findings:
        print("  \033[0;32m✔ No vulnerabilities found.\033[0m")
        print(f"{'='*70}\n")
        return

    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print(f"  Total findings: {len(findings)}")
    for sev, count in sorted(counts.items(), key=lambda x: SEVERITY_ORDER.get(x[0], 99)):
        color = SEVERITY_BADGE.get(sev, "")
        print(f"    {color}{sev}: {count}{RESET}")
    print(f"{'='*70}")

    for i, f in enumerate(findings, 1):
        color = SEVERITY_BADGE.get(f["severity"], "")
        print(f"\n[{i}] {color}{f['severity']}{RESET} — {f['type']}: {f['subtype']}")
        print(f"     URL:       {f['url']}")
        if f.get("parameter"):
            print(f"     Parameter: {f['parameter']}")
        print(f"     Method:    {f['method']}")
        if f.get("payload"):
            print(f"     Payload:   {f['payload'][:80]}")
        print(f"     Evidence:  {f['evidence']}")
        if f.get("recommendation"):
            print(f"     Fix:       {f['recommendation']}")

    print(f"\n{'='*70}\n")


# ── JSON ──────────────────────────────────────────────────────────────────────

def save_json(findings: List[Dict], target: str, output_path: str):
    report = {
        "tool": "WebVulnScan",
        "version": "1.0.0",
        "target": target,
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "total": len(findings),
        "findings": _sort_findings(findings),
    }
    Path(output_path).write_text(json.dumps(report, indent=2))
    print(f"[+] JSON report saved: {output_path}")


# ── HTML ──────────────────────────────────────────────────────────────────────

def save_html(findings: List[Dict], target: str, output_path: str):
    findings = _sort_findings(findings)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    rows = ""
    for f in findings:
        color = SEVERITY_COLORS.get(f["severity"], "#999")
        payload = (f.get("payload") or "")[:100]
        recommendation = f.get("recommendation", "")
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{f['severity']}</span></td>
          <td>{f['type']}</td>
          <td>{f['subtype']}</td>
          <td class="url">{f['url']}</td>
          <td>{f.get('parameter') or '-'}</td>
          <td>{f['method']}</td>
          <td class="payload">{payload or '-'}</td>
          <td>{f['evidence']}</td>
          <td>{recommendation or '-'}</td>
        </tr>"""

    summary = ""
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        c = counts.get(sev, 0)
        color = SEVERITY_COLORS[sev]
        summary += f'<div class="stat"><div class="stat-num" style="color:{color}">{c}</div><div class="stat-label">{sev}</div></div>'

    if not findings:
        table_section = "<div class='empty'>&#9989; No vulnerabilities found.</div>"
    else:
        table_section = (
            "<table><thead><tr>"
            "<th>Severity</th><th>Type</th><th>Subtype</th><th>URL</th>"
            "<th>Parameter</th><th>Method</th><th>Payload</th><th>Evidence</th><th>Recommendation</th>"
            "</tr></thead><tbody>" + rows + "</tbody></table>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>WebVulnScan Report — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; }}
  header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 24px 40px; }}
  header h1 {{ font-size: 1.4rem; color: #58a6ff; letter-spacing: 0.5px; }}
  header p {{ font-size: 0.85rem; color: #8b949e; margin-top: 4px; }}
  .summary {{ display: flex; gap: 24px; padding: 24px 40px; background: #161b22; border-bottom: 1px solid #30363d; }}
  .stat {{ text-align: center; }}
  .stat-num {{ font-size: 2rem; font-weight: 700; }}
  .stat-label {{ font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }}
  .container {{ padding: 24px 40px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
  th {{ background: #21262d; color: #8b949e; text-align: left; padding: 10px 12px; border-bottom: 1px solid #30363d; white-space: nowrap; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }}
  tr:hover td {{ background: #1c2128; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; color: #fff; font-size: 0.75rem; font-weight: 600; }}
  .url {{ color: #58a6ff; word-break: break-all; max-width: 200px; }}
  .payload {{ font-family: monospace; font-size: 0.78rem; color: #f0883e; max-width: 180px; word-break: break-all; }}
  .empty {{ text-align: center; padding: 60px; color: #3fb950; font-size: 1.1rem; }}
</style>
</head>
<body>
<header>
  <h1>🔍 WebVulnScan — Security Report</h1>
  <p>Target: <strong>{target}</strong> &nbsp;|&nbsp; Generated: {now} &nbsp;|&nbsp; Total Findings: {len(findings)}</p>
</header>
<div class="summary">{summary}</div>
<div class="container">
{table_section}
</div>
</body>
</html>"""

    Path(output_path).write_text(html)
    print(f"[+] HTML report saved: {output_path}")
