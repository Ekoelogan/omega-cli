"""ReverseAgent — reverse engineering and firmware analysis specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class ReverseAgent(BaseAgent):
    name = "reverse-agent"
    description = "Reverse engineering — firmware analysis, binary inspection, code review"
    category = "reverse-engineering"
    capabilities = ["firmware_analysis", "binary_inspection", "code_review"]
    tools = ["firmware"]

    def plan(self) -> list[str]:
        return [
            "Extract and analyze firmware images",
            "Search for hardcoded credentials and keys",
            "Identify debug interfaces and backdoors",
            "Check for known vulnerable firmware versions",
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
        firmware_data = data.get("firmware", {})
        if isinstance(firmware_data, dict):
            # Hardcoded credentials
            hardcoded = firmware_data.get("hardcoded_creds", firmware_data.get("credentials", []))
            if isinstance(hardcoded, list) and hardcoded:
                self.add_finding(
                    f"Hardcoded Credentials in Firmware ({len(hardcoded)})",
                    Severity.CRITICAL,
                    f"Found {len(hardcoded)} hardcoded credential(s) embedded in firmware. "
                    "These cannot be changed by end users and are often shared across all devices.",
                    evidence=f"{len(hardcoded)} credential(s) found in firmware image",
                    recommendation="Remove hardcoded credentials from firmware. Use secure "
                    "provisioning with unique per-device credentials.",
                    tags=["reverse-engineering", "firmware", "hardcoded-creds", "critical-risk"],
                )

            # Debug interfaces
            debug = firmware_data.get("debug_interfaces", firmware_data.get("debug", []))
            if isinstance(debug, list) and debug:
                self.add_finding(
                    f"Debug Interfaces Exposed ({len(debug)})",
                    Severity.HIGH,
                    f"Found {len(debug)} active debug interface(s) (JTAG, UART, serial console). "
                    "Debug interfaces allow full device access and firmware extraction.",
                    evidence=", ".join(str(d) for d in debug[:5]),
                    recommendation="Disable debug interfaces in production firmware. "
                    "Use hardware fuses to permanently disable JTAG.",
                    tags=["reverse-engineering", "debug", "hardware"],
                )

            # Known vulnerable firmware versions
            versions = firmware_data.get("versions", firmware_data.get("firmware_version", {}))
            cves = firmware_data.get("cves", firmware_data.get("known_vulns", []))
            if isinstance(cves, list) and cves:
                self.add_finding(
                    f"Known CVEs in Firmware ({len(cves)})",
                    Severity.HIGH,
                    f"Firmware version has {len(cves)} known CVE(s). "
                    "Attackers may have public exploits for these vulnerabilities.",
                    evidence=", ".join(str(c) for c in cves[:10]),
                    recommendation="Update firmware to the latest patched version. "
                    "Monitor vendor advisories for security updates.",
                    tags=["reverse-engineering", "firmware", "cve"],
                )
            elif versions:
                self.add_finding(
                    "Firmware Version Identified",
                    Severity.INFO,
                    f"Firmware version information extracted: {str(versions)[:200]}",
                    evidence=str(versions)[:300],
                    tags=["reverse-engineering", "firmware", "version"],
                )

            # Encryption keys / certificates
            keys = firmware_data.get("keys", firmware_data.get("certificates", []))
            if isinstance(keys, list) and keys:
                self.add_finding(
                    f"Embedded Cryptographic Keys ({len(keys)})",
                    Severity.HIGH,
                    f"Found {len(keys)} cryptographic key(s) or certificate(s) embedded "
                    "in firmware. Extraction enables impersonation and decryption attacks.",
                    evidence=f"{len(keys)} key(s)/certificate(s) extracted",
                    recommendation="Use hardware security modules (HSM) or secure enclaves "
                    "for key storage. Never embed private keys in firmware.",
                    tags=["reverse-engineering", "crypto-keys", "firmware"],
                )

            # Binary protections check
            protections = firmware_data.get("protections", firmware_data.get("security_features", {}))
            if isinstance(protections, dict):
                missing = []
                checks = {
                    "aslr": "ASLR",
                    "stack_canary": "Stack Canaries",
                    "nx": "NX/DEP",
                    "pie": "PIE",
                    "relro": "RELRO",
                }
                for key, label in checks.items():
                    if not protections.get(key, True):
                        missing.append(label)

                if missing:
                    self.add_finding(
                        f"Missing Binary Protections ({len(missing)})",
                        Severity.MEDIUM,
                        f"Firmware binaries lack the following protections: "
                        f"{', '.join(missing)}. This increases exploitability.",
                        evidence=f"Missing: {', '.join(missing)}",
                        recommendation="Enable all binary hardening features: "
                        "ASLR, stack canaries, NX, PIE, full RELRO.",
                        tags=["reverse-engineering", "binary-hardening"],
                    )

        return self.findings

    def handoff(self) -> list[str]:
        has_vulns = any(
            f.severity in (Severity.CRITICAL, Severity.HIGH)
            for f in self.findings
        )
        return ["exploit-agent"] if has_vulns else []
