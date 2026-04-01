"""VulnAgent — vulnerability assessment specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class VulnAgent(BaseAgent):
    name = "vuln-agent"
    description = "Vulnerability assessment — CVE mapping, misconfiguration detection, risk scoring"
    category = "vulnerability"
    capabilities = ["cve_lookup", "vuln_scanning", "risk_scoring", "port_analysis"]
    tools = ["vuln", "cve", "ports", "ssl", "spoofcheck"]

    def plan(self) -> list[str]:
        return [
            "Port scan and service detection",
            "SSL/TLS analysis",
            "CVE mapping for detected technologies",
            "Email spoofing vulnerability check",
            "Vulnerability correlation and risk scoring",
        ]

    def execute(self) -> dict[str, Any]:
        data = {}
        # Also check memory for existing recon data
        if self.memory:
            prior_runs = self.memory.get_runs(target=self.target)
            for run in prior_runs:
                run_data = self.memory.get_run_data(run["id"])
                if run_data:
                    data[f"prior_{run['agent']}"] = run_data

        for tool_name in self.tools:
            self.log(f"Running {tool_name}...")
            try:
                result = self.executor.run_omega(tool_name, self.target)
                if result.success and result.data:
                    data[tool_name] = result.data
                elif result.success:
                    data[tool_name] = {"output": result.output[:3000]}
                else:
                    self.log(f"  {tool_name}: {result.error}")
            except Exception as e:
                self.log(f"  {tool_name} error: {e}")
        return data

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        # Port analysis
        port_data = data.get("ports", {})
        if isinstance(port_data, dict):
            open_ports = port_data.get("ports", port_data.get("open", []))
            risky_ports = {
                21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP",
                1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL",
                6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
            }
            for port_info in (open_ports if isinstance(open_ports, list) else []):
                port_num = port_info.get("port", port_info) if isinstance(port_info, dict) else port_info
                if isinstance(port_num, int) and port_num in risky_ports:
                    self.add_finding(
                        f"Exposed {risky_ports[port_num]} Service (port {port_num})",
                        Severity.HIGH,
                        f"Port {port_num} ({risky_ports[port_num]}) is exposed to the internet. "
                        "This service should not be publicly accessible.",
                        recommendation=f"Restrict access to port {port_num} via firewall rules. "
                        "Use VPN for remote access.",
                        tags=["ports", "exposure", risky_ports[port_num].lower()],
                    )

        # SSL analysis
        ssl_data = data.get("ssl", {})
        if isinstance(ssl_data, dict):
            if ssl_data.get("expired"):
                self.add_finding(
                    "Expired SSL Certificate",
                    Severity.CRITICAL,
                    "The SSL certificate has expired, causing browser warnings and trust issues.",
                    recommendation="Renew the SSL certificate immediately.",
                    tags=["ssl", "certificate"],
                )
            proto = str(ssl_data.get("protocol", "")).lower()
            if "tls 1.0" in proto or "tls 1.1" in proto or "ssl" in proto:
                self.add_finding(
                    "Weak TLS Version",
                    Severity.HIGH,
                    f"Server supports deprecated protocol: {proto}",
                    recommendation="Disable TLS 1.0/1.1 and SSLv3. Use TLS 1.2+ only.",
                    tags=["ssl", "tls", "deprecated"],
                )

        # Spoofcheck
        spoof_data = data.get("spoofcheck", {})
        if isinstance(spoof_data, dict):
            if spoof_data.get("spoofable") or not spoof_data.get("dmarc"):
                self.add_finding(
                    "Email Spoofing Vulnerability",
                    Severity.MEDIUM,
                    "Domain may be vulnerable to email spoofing due to missing or weak "
                    "SPF/DKIM/DMARC configuration.",
                    recommendation="Implement strict DMARC policy (p=reject) with SPF and DKIM.",
                    tags=["email", "spoofing", "dmarc"],
                )

        return self.findings

    def handoff(self) -> list[str]:
        has_critical = any(f.severity == Severity.CRITICAL for f in self.findings)
        if has_critical:
            return ["report-agent"]
        return []
