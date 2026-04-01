"""PrivacyAgent — anonymity and privacy analysis specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class PrivacyAgent(BaseAgent):
    name = "privacy-agent"
    description = "Anonymity & privacy — Tor checks, OPSEC analysis, dark web presence"
    category = "privacy"
    capabilities = ["tor_check", "opsec_audit", "darkweb_search"]
    tools = ["torcheck", "opsec", "dark", "deepweb"]

    def plan(self) -> list[str]:
        return [
            "Check for Tor exit node exposure",
            "Perform OPSEC audit on target identity",
            "Search dark web for mentions and leaked data",
            "Search deep web forums and marketplaces",
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
                    self.log(f"  {tool_name}: {result.error}")
            except Exception as e:
                self.log(f"  {tool_name} error: {e}")
        return data

    def analyze(self, data: dict[str, Any]) -> list[Finding]:
        # Tor check analysis
        tor_data = data.get("torcheck", {})
        if isinstance(tor_data, dict):
            is_exit = tor_data.get("is_exit_node", tor_data.get("exit_node", False))
            is_relay = tor_data.get("is_relay", tor_data.get("relay", False))
            if is_exit:
                self.add_finding(
                    "Tor Exit Node Identified",
                    Severity.HIGH,
                    "Target IP is identified as a Tor exit node. Traffic from this IP "
                    "may originate from anonymous Tor users, including malicious actors.",
                    evidence=str(tor_data)[:300],
                    recommendation="Apply enhanced monitoring for traffic from Tor exit nodes. "
                    "Consider blocking or rate-limiting Tor exit IPs for sensitive services.",
                    tags=["privacy", "tor", "exit-node", "anonymity"],
                )
            elif is_relay:
                self.add_finding(
                    "Tor Relay Node Detected",
                    Severity.MEDIUM,
                    "Target IP operates as a Tor relay, participating in the Tor network. "
                    "While not an exit node, it routes anonymized traffic.",
                    evidence=str(tor_data)[:300],
                    recommendation="Monitor the relay for abuse. Review hosting policies "
                    "regarding Tor relay operation.",
                    tags=["privacy", "tor", "relay"],
                )

        # OPSEC analysis
        opsec_data = data.get("opsec", {})
        if isinstance(opsec_data, dict):
            failures = opsec_data.get("failures", opsec_data.get("issues", []))
            if isinstance(failures, list) and failures:
                sev = Severity.HIGH if len(failures) >= 3 else Severity.MEDIUM
                self.add_finding(
                    f"OPSEC Failures Identified ({len(failures)})",
                    sev,
                    f"Found {len(failures)} operational security failure(s) that may "
                    "allow de-anonymization or identity correlation.",
                    evidence=", ".join(str(f) for f in failures[:5]),
                    recommendation="Address OPSEC failures: use separate identities, "
                    "avoid cross-platform username reuse, sanitize metadata.",
                    tags=["privacy", "opsec", "identity-correlation"],
                )

            # Real identity exposure
            real_id = opsec_data.get("real_identity", opsec_data.get("deanon", {}))
            if isinstance(real_id, dict) and real_id:
                self.add_finding(
                    "Potential Real Identity Exposure",
                    Severity.CRITICAL,
                    "OPSEC analysis suggests the target's real identity may be "
                    "discoverable through correlation of online activities.",
                    evidence=str(real_id)[:500],
                    recommendation="Review and compartmentalize online identities. "
                    "Use dedicated devices and accounts for sensitive activities.",
                    tags=["privacy", "opsec", "deanonymization", "identity"],
                )

        # Dark web mentions
        dark_data = data.get("dark", {})
        if isinstance(dark_data, dict):
            mentions = dark_data.get("mentions", dark_data.get("results", []))
            if isinstance(mentions, list) and mentions:
                # Categorize by threat level
                marketplace_hits = []
                forum_hits = []
                paste_hits = []
                for mention in mentions:
                    if isinstance(mention, dict):
                        source = str(mention.get("source", mention.get("type", ""))).lower()
                        if "market" in source:
                            marketplace_hits.append(mention)
                        elif "forum" in source:
                            forum_hits.append(mention)
                        elif "paste" in source:
                            paste_hits.append(mention)

                if marketplace_hits:
                    self.add_finding(
                        f"Dark Web Marketplace Mentions ({len(marketplace_hits)})",
                        Severity.CRITICAL,
                        f"Target found in {len(marketplace_hits)} dark web marketplace listing(s). "
                        "Data or credentials may be available for sale.",
                        evidence=str(marketplace_hits)[:500],
                        recommendation="Initiate breach response. Change all credentials. "
                        "Monitor for unauthorized access.",
                        tags=["privacy", "dark-web", "marketplace"],
                    )

                if forum_hits:
                    self.add_finding(
                        f"Dark Web Forum Mentions ({len(forum_hits)})",
                        Severity.HIGH,
                        f"Target discussed in {len(forum_hits)} dark web forum post(s).",
                        evidence=str(forum_hits)[:500],
                        recommendation="Monitor for evolving threats. "
                        "Assess potential targeted attack risk.",
                        tags=["privacy", "dark-web", "forum"],
                    )

                if paste_hits:
                    self.add_finding(
                        f"Dark Web Paste Mentions ({len(paste_hits)})",
                        Severity.MEDIUM,
                        f"Target found in {len(paste_hits)} paste site(s) on the dark web.",
                        evidence=str(paste_hits)[:500],
                        recommendation="Review paste content for leaked credentials or sensitive data.",
                        tags=["privacy", "dark-web", "paste"],
                    )

        # Deep web analysis
        deep_data = data.get("deepweb", {})
        if isinstance(deep_data, dict):
            results = deep_data.get("results", deep_data.get("findings", []))
            if isinstance(results, list) and results:
                self.add_finding(
                    f"Deep Web Presence Detected ({len(results)} results)",
                    Severity.MEDIUM,
                    f"Found {len(results)} reference(s) to the target on deep web "
                    "sources (non-indexed sites, private databases, archives).",
                    evidence=str(results)[:500],
                    recommendation="Audit exposed information. Request removal where possible.",
                    tags=["privacy", "deep-web"],
                )

        return self.findings

    def handoff(self) -> list[str]:
        has_identity = any(
            "identity" in f.title.lower() or "opsec" in f.title.lower()
            or "deanon" in " ".join(f.tags)
            for f in self.findings
        )
        return ["social-agent"] if has_identity else []
