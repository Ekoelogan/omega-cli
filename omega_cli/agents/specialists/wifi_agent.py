"""WifiAgent — wireless testing and reconnaissance specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class WifiAgent(BaseAgent):
    name = "wifi-agent"
    description = "Wireless testing — WiFi analysis, signal reconnaissance, AP discovery"
    category = "wireless"
    capabilities = ["wifi_scan", "ap_discovery", "signal_analysis"]
    tools = ["network"]

    def plan(self) -> list[str]:
        return [
            "Scan for nearby wireless access points",
            "Identify encryption types and security protocols",
            "Analyze signal strength and channel usage",
            "Detect rogue or misconfigured access points",
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
        network_data = data.get("network", {})
        if isinstance(network_data, dict):
            # Analyze access points
            access_points = network_data.get("access_points", network_data.get("aps", []))
            if isinstance(access_points, list):
                open_networks = []
                wep_networks = []
                weak_networks = []

                for ap in access_points:
                    if not isinstance(ap, dict):
                        continue
                    ssid = ap.get("ssid", ap.get("name", "Unknown"))
                    encryption = str(ap.get("encryption", ap.get("security", ""))).upper()
                    signal = ap.get("signal", ap.get("rssi", 0))

                    if encryption in ("OPEN", "NONE", ""):
                        open_networks.append(ssid)
                    elif "WEP" in encryption:
                        wep_networks.append(ssid)
                    elif "WPA" in encryption and "WPA2" not in encryption and "WPA3" not in encryption:
                        weak_networks.append(ssid)

                if open_networks:
                    self.add_finding(
                        f"Open WiFi Networks Detected ({len(open_networks)})",
                        Severity.CRITICAL,
                        f"Found {len(open_networks)} wireless network(s) with no encryption. "
                        "Traffic is transmitted in plaintext, enabling eavesdropping.",
                        evidence=", ".join(open_networks[:10]),
                        recommendation="Enable WPA3 or WPA2-Enterprise encryption on all access points. "
                        "Never use open networks for sensitive traffic.",
                        tags=["wifi", "open-network", "no-encryption"],
                    )

                if wep_networks:
                    self.add_finding(
                        f"WEP Encrypted Networks ({len(wep_networks)})",
                        Severity.HIGH,
                        f"Found {len(wep_networks)} network(s) using WEP encryption. "
                        "WEP is cryptographically broken and can be cracked in minutes.",
                        evidence=", ".join(wep_networks[:10]),
                        recommendation="Upgrade to WPA3 or WPA2 immediately. "
                        "WEP provides no meaningful security.",
                        tags=["wifi", "wep", "weak-encryption"],
                    )

                if weak_networks:
                    self.add_finding(
                        f"Weak WPA Networks ({len(weak_networks)})",
                        Severity.MEDIUM,
                        f"Found {len(weak_networks)} network(s) using WPA (not WPA2/WPA3). "
                        "WPA-TKIP has known weaknesses.",
                        evidence=", ".join(weak_networks[:10]),
                        recommendation="Upgrade to WPA2-AES or WPA3.",
                        tags=["wifi", "wpa", "weak-encryption"],
                    )

                if access_points and not (open_networks or wep_networks or weak_networks):
                    self.add_finding(
                        f"WiFi Networks Scanned ({len(access_points)} APs)",
                        Severity.INFO,
                        f"Discovered {len(access_points)} access points, all using adequate encryption.",
                        tags=["wifi", "scan-complete"],
                    )

            # Check for hidden SSIDs
            hidden = network_data.get("hidden_ssids", network_data.get("hidden", []))
            if isinstance(hidden, list) and hidden:
                self.add_finding(
                    f"Hidden SSIDs Detected ({len(hidden)})",
                    Severity.LOW,
                    f"Found {len(hidden)} hidden SSID(s). Hidden SSIDs provide no real security "
                    "and can be easily discovered via probe requests.",
                    evidence=str(hidden)[:300],
                    recommendation="Do not rely on SSID hiding for security. "
                    "Use strong encryption and authentication instead.",
                    tags=["wifi", "hidden-ssid"],
                )

            # Check for rogue access points
            rogues = network_data.get("rogue_aps", network_data.get("rogues", []))
            if isinstance(rogues, list) and rogues:
                self.add_finding(
                    f"Potential Rogue Access Points ({len(rogues)})",
                    Severity.HIGH,
                    f"Detected {len(rogues)} potential rogue AP(s) that may be performing "
                    "evil twin or man-in-the-middle attacks.",
                    evidence=str(rogues)[:500],
                    recommendation="Investigate and remove unauthorized access points. "
                    "Deploy wireless intrusion detection (WIDS).",
                    tags=["wifi", "rogue-ap", "evil-twin"],
                )

        return self.findings

    def handoff(self) -> list[str]:
        has_weak = any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)
        return ["exploit-agent"] if has_weak else []
