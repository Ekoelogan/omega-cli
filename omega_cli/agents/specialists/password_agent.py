"""PasswordAgent — password and credential analysis specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class PasswordAgent(BaseAgent):
    name = "password-agent"
    description = "Password & credential analysis — wordlist generation, breach checks, credential auditing"
    category = "password"
    capabilities = ["wordlist_gen", "breach_check", "credential_audit"]
    tools = ["wordlist", "creds", "breach"]

    def plan(self) -> list[str]:
        return [
            "Generate target-specific wordlists",
            "Check credentials against known breach databases",
            "Audit credential strength and policy compliance",
            "Identify reused or default credentials",
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
        # Breach data analysis
        breach_data = data.get("breach", {})
        if isinstance(breach_data, dict):
            breaches = breach_data.get("breaches", breach_data.get("results", []))
            if isinstance(breaches, list) and breaches:
                passwords_exposed = sum(
                    1 for b in breaches
                    if isinstance(b, dict) and b.get("password_exposed", b.get("has_password", False))
                )
                self.add_finding(
                    f"Credentials in {len(breaches)} Data Breaches",
                    Severity.HIGH if passwords_exposed else Severity.MEDIUM,
                    f"Target appears in {len(breaches)} known breach(es). "
                    f"{'Plaintext/hashed passwords were exposed in ' + str(passwords_exposed) + ' breach(es).' if passwords_exposed else 'Email/username exposed but passwords may not be included.'}",
                    evidence=", ".join(
                        str(b.get("name", b.get("source", b))) for b in breaches[:8]
                        if isinstance(b, dict)
                    ) or str(breaches[:5]),
                    recommendation="Force password resets for affected accounts. "
                    "Enable multi-factor authentication. Monitor for credential stuffing attempts.",
                    tags=["breach", "credential-exposure", "password-leak"],
                )

        # Credential audit analysis
        creds_data = data.get("creds", {})
        if isinstance(creds_data, dict):
            # Default credentials
            defaults = creds_data.get("default_creds", creds_data.get("defaults", []))
            if isinstance(defaults, list) and defaults:
                self.add_finding(
                    f"Default Credentials Detected ({len(defaults)})",
                    Severity.CRITICAL,
                    f"Found {len(defaults)} service(s) using default or factory credentials. "
                    "Attackers routinely check for default credentials.",
                    evidence=", ".join(
                        str(d.get("service", d)) for d in defaults[:5]
                        if isinstance(d, dict)
                    ) or str(defaults[:5]),
                    recommendation="Change all default credentials immediately. "
                    "Implement credential rotation policies.",
                    tags=["credentials", "default-password", "critical-risk"],
                )

            # Weak passwords
            weak = creds_data.get("weak_passwords", creds_data.get("weak", []))
            if isinstance(weak, list) and weak:
                self.add_finding(
                    f"Weak Passwords Identified ({len(weak)} accounts)",
                    Severity.HIGH,
                    f"Found {len(weak)} account(s) with weak passwords that fail "
                    "complexity requirements or match common patterns.",
                    evidence=f"{len(weak)} accounts flagged for weak credentials",
                    recommendation="Enforce minimum password length of 14+ characters. "
                    "Block common passwords via deny lists. Require MFA.",
                    tags=["credentials", "weak-password", "policy-violation"],
                )

            # Reused credentials
            reused = creds_data.get("reused", creds_data.get("duplicates", []))
            if isinstance(reused, list) and reused:
                self.add_finding(
                    f"Password Reuse Detected ({len(reused)} instances)",
                    Severity.MEDIUM,
                    "Same password used across multiple accounts or services. "
                    "Compromise of one account jeopardizes all reused accounts.",
                    evidence=f"{len(reused)} credential reuse instance(s) detected",
                    recommendation="Use unique passwords per service. Deploy a password manager. "
                    "Implement credential correlation monitoring.",
                    tags=["credentials", "password-reuse"],
                )

        # Wordlist analysis
        wordlist_data = data.get("wordlist", {})
        if isinstance(wordlist_data, dict):
            word_count = wordlist_data.get("count", wordlist_data.get("size", 0))
            if word_count:
                self.add_finding(
                    f"Custom Wordlist Generated ({word_count} entries)",
                    Severity.INFO,
                    f"Generated a target-specific wordlist with {word_count} entries "
                    "from OSINT data for password auditing.",
                    tags=["wordlist", "password-audit"],
                )

        return self.findings

    def handoff(self) -> list[str]:
        has_creds = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.findings
        )
        return ["exploit-agent"] if has_creds else []
