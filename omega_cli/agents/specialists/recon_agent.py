"""ReconAgent — full passive reconnaissance specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class ReconAgent(BaseAgent):
    name = "recon-agent"
    description = "Passive OSINT reconnaissance — WHOIS, DNS, subdomains, certificates, IPs"
    category = "recon"
    capabilities = ["whois", "dns", "subdomain_enum", "cert_transparency", "ip_intel", "tech_fingerprint"]
    tools = ["whois", "dns", "subdomain", "crtsh", "ipinfo", "tech", "asn", "reverseip", "dorks"]

    def plan(self) -> list[str]:
        return [
            "WHOIS lookup",
            "DNS record enumeration",
            "Certificate transparency (crt.sh)",
            "Subdomain enumeration",
            "IP intelligence",
            "Technology fingerprinting",
            "ASN reconnaissance",
            "Google dorks generation",
        ]

    def execute(self) -> dict[str, Any]:
        data = {}
        for tool_name in self.tools:
            self.log(f"Running {tool_name}...")
            try:
                result = self.executor.run_omega(tool_name, self.target)
                if result.success and result.data:
                    data[tool_name] = result.data
                elif result.success:
                    data[tool_name] = {"output": result.output[:3000]}
                else:
                    self.log(f"  {tool_name} failed: {result.error}")
            except Exception as e:
                self.log(f"  {tool_name} error: {e}")
        return data

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        findings = []

        # Analyze WHOIS data
        whois_data = data.get("whois", {})
        if isinstance(whois_data, dict):
            if whois_data.get("privacy") or "proxy" in str(whois_data).lower():
                self.add_finding(
                    "WHOIS Privacy Enabled",
                    Severity.INFO,
                    "Domain uses WHOIS privacy protection, limiting registrant visibility.",
                    tags=["whois", "privacy"],
                )

        # Analyze subdomains
        sub_data = data.get("subdomain", {})
        subs = sub_data if isinstance(sub_data, list) else sub_data.get("subdomains", [])
        if len(subs) > 20:
            self.add_finding(
                f"Large Subdomain Surface ({len(subs)} found)",
                Severity.MEDIUM,
                f"Discovered {len(subs)} subdomains — indicates large attack surface. "
                "Review for staging/dev/legacy systems.",
                evidence=", ".join(subs[:10]),
                recommendation="Audit subdomains for unnecessary exposure. Remove staging/dev systems.",
                tags=["subdomains", "attack-surface"],
            )
        elif subs:
            self.add_finding(
                f"Subdomains Discovered ({len(subs)})",
                Severity.INFO,
                f"Found {len(subs)} subdomains for {self.target}.",
                evidence=", ".join(subs[:10]),
                tags=["subdomains"],
            )

        # Analyze DNS
        dns_data = data.get("dns", {})
        if isinstance(dns_data, dict):
            if not dns_data.get("DMARC") and not dns_data.get("dmarc"):
                self.add_finding(
                    "Missing DMARC Record",
                    Severity.MEDIUM,
                    "No DMARC record found — domain may be vulnerable to email spoofing.",
                    recommendation="Add a DMARC record: _dmarc.{target} TXT 'v=DMARC1; p=reject; ...'",
                    tags=["dns", "email-security", "dmarc"],
                )

        # Analyze tech fingerprint
        tech_data = data.get("tech", {})
        if isinstance(tech_data, dict):
            techs = tech_data.get("technologies", tech_data)
            if isinstance(techs, (list, dict)):
                tech_str = str(techs)
                old_tech = ["php/5", "apache/2.2", "iis/7", "jquery/1.", "angular/1."]
                for old in old_tech:
                    if old in tech_str.lower():
                        self.add_finding(
                            f"Outdated Technology Detected",
                            Severity.HIGH,
                            f"Found potentially outdated technology matching '{old}'. "
                            "Older versions may have known CVEs.",
                            evidence=tech_str[:200],
                            recommendation="Upgrade to the latest stable version.",
                            tags=["tech", "outdated", "cve-risk"],
                        )

        # Analyze certificate data
        crt_data = data.get("crtsh", {})
        if isinstance(crt_data, (list, dict)):
            certs = crt_data if isinstance(crt_data, list) else crt_data.get("certificates", [])
            if len(certs) > 50:
                self.add_finding(
                    f"Large Certificate Footprint ({len(certs)} certs)",
                    Severity.LOW,
                    f"Certificate transparency logs show {len(certs)} certificates — "
                    "indicates extensive infrastructure.",
                    tags=["certificates", "infrastructure"],
                )

        return self.findings

    def handoff(self) -> list[str]:
        agents = []
        has_subs = any(f.title.startswith("Subdomain") or f.title.startswith("Large Subdomain")
                       for f in self.findings)
        has_old_tech = any("Outdated" in f.title for f in self.findings)
        if has_subs:
            agents.append("web-agent")
        if has_old_tech:
            agents.append("vuln-agent")
        return agents
