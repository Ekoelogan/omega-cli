"""ReportAgent — generates aggregated findings reports in multiple formats."""
from __future__ import annotations

import json
import datetime
from pathlib import Path
from typing import Any, Optional

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class ReportAgent(BaseAgent):
    name = "report-agent"
    description = "Report generation — aggregates all agent findings into PDF/HTML/JSON reports"
    category = "reporting"
    capabilities = ["json_report", "html_report", "pdf_report", "executive_summary"]
    tools = []

    def plan(self) -> list[str]:
        return [
            "Collect findings from all prior agents",
            "Aggregate and deduplicate",
            "Generate JSON report",
            "Generate HTML report",
            "Produce executive summary",
        ]

    def execute(self) -> dict[str, Any]:
        data = {"findings": [], "runs": []}
        if self.memory:
            data["findings"] = self.memory.get_findings(target=self.target, limit=500)
            data["runs"] = self.memory.get_runs(target=self.target)
            data["stats"] = self.memory.stats()
        return data

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        findings = data.get("findings", [])
        if not findings:
            self.add_finding(
                "No Findings to Report",
                Severity.INFO,
                "No prior findings were found in memory for this target.",
                tags=["report"],
            )
            return self.findings

        # Generate the report files
        self._write_reports(data)

        critical = sum(1 for f in findings if f.get("severity") == "critical")
        high = sum(1 for f in findings if f.get("severity") == "high")
        medium = sum(1 for f in findings if f.get("severity") == "medium")

        self.add_finding(
            f"Report Generated — {len(findings)} Findings",
            Severity.INFO,
            f"Aggregated report for {self.target}: "
            f"{critical} critical, {high} high, {medium} medium findings. "
            f"Reports saved to ~/omega-reports/{self.target.replace('.', '_')}/",
            tags=["report", "aggregate"],
        )

        return self.findings

    def _write_reports(self, data: dict):
        """Write JSON and HTML reports to disk."""
        findings = data.get("findings", [])
        ts = datetime.datetime.now()
        slug = self.target.replace(".", "_").replace("/", "_")
        out_dir = Path.home() / "omega-reports" / slug
        out_dir.mkdir(parents=True, exist_ok=True)

        ts_str = ts.strftime("%Y%m%d_%H%M")

        # JSON report
        json_path = out_dir / f"omega_agent_{slug}_{ts_str}.json"
        report = {
            "target": self.target,
            "generated": ts.isoformat(),
            "generator": "omega-agent-framework",
            "summary": {
                "total_findings": len(findings),
                "by_severity": {},
                "agents_run": list(set(f.get("agent", "") for f in findings)),
            },
            "findings": findings,
        }
        for f in findings:
            sev = f.get("severity", "info")
            report["summary"]["by_severity"][sev] = report["summary"]["by_severity"].get(sev, 0) + 1

        with open(json_path, "w") as fh:
            json.dump(report, fh, indent=2, default=str)
        self.log(f"JSON report → {json_path}")

        # HTML report
        html_path = out_dir / f"omega_agent_{slug}_{ts_str}.html"
        html = self._build_html(report)
        with open(html_path, "w") as fh:
            fh.write(html)
        self.log(f"HTML report → {html_path}")

    def _build_html(self, report: dict) -> str:
        target = report["target"]
        findings = report["findings"]
        summary = report["summary"]
        ts = report["generated"]

        sev_colors = {
            "critical": "#f85149", "high": "#f0883e",
            "medium": "#d29922", "low": "#39c5cf", "info": "#8b949e",
        }

        finding_rows = ""
        for f in findings:
            sev = f.get("severity", "info")
            color = sev_colors.get(sev, "#8b949e")
            finding_rows += f"""
            <tr>
                <td><span style="color:{color};font-weight:bold">{sev.upper()}</span></td>
                <td>{f.get('title', '')}</td>
                <td>{f.get('agent', '')}</td>
                <td style="font-size:0.85em">{f.get('description', '')[:200]}</td>
            </tr>"""

        by_sev = summary.get("by_severity", {})
        sev_badges = " ".join(
            f'<span style="background:rgba(255,255,255,0.1);padding:2px 8px;border-radius:4px;'
            f'color:{sev_colors.get(s, "#8b949e")}">{by_sev[s]} {s}</span>'
            for s in ["critical", "high", "medium", "low", "info"] if s in by_sev
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><title>OMEGA Agent Report — {target}</title>
<style>
  :root {{ --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3; }}
  body {{ background:var(--bg); color:var(--text); font-family:system-ui,sans-serif; padding:2rem; }}
  h1 {{ color:#ff2d78; }} h2 {{ color:#ff85b3; }}
  table {{ width:100%; border-collapse:collapse; margin:1rem 0; }}
  th,td {{ padding:8px 12px; border-bottom:1px solid var(--border); text-align:left; }}
  th {{ color:#ff85b3; font-size:0.85em; text-transform:uppercase; }}
  .card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin:1rem 0; }}
</style>
</head>
<body>
<h1>🤖 OMEGA Agent Report — {target}</h1>
<p style="color:#8b949e">Generated: {ts} | Agents: {', '.join(summary.get('agents_run', []))}</p>
<div class="card">
  <h2>Summary</h2>
  <p>{summary['total_findings']} total findings: {sev_badges}</p>
</div>
<div class="card">
  <h2>Findings</h2>
  <table>
    <tr><th>Severity</th><th>Title</th><th>Agent</th><th>Description</th></tr>
    {finding_rows}
  </table>
</div>
<footer style="text-align:center;color:#8b949e;margin-top:3rem;font-size:0.8em">
  OMEGA-OS Agent Framework — passive recon only — authorized use only
</footer>
</body></html>"""

    def handoff(self) -> list[str]:
        return []
