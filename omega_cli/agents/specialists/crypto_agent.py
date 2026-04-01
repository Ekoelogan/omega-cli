"""CryptoAgent — cryptocurrency and steganography analysis specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class CryptoAgent(BaseAgent):
    name = "crypto-agent"
    description = "Crypto & steganography — blockchain analysis, cryptocurrency tracing, stego detection"
    category = "crypto"
    capabilities = ["blockchain_trace", "crypto_analysis", "stego_detection"]
    tools = ["crypto", "cryptoosint"]

    def plan(self) -> list[str]:
        return [
            "Analyze blockchain transactions and wallet addresses",
            "Trace cryptocurrency flows for suspicious patterns",
            "Check addresses against sanctions and blacklists",
            "Detect steganographic content in media files",
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
        # Crypto / blockchain analysis
        crypto_data = data.get("crypto", {})
        if isinstance(crypto_data, dict):
            # Sanctioned address check
            sanctions = crypto_data.get("sanctions", crypto_data.get("blacklisted", {}))
            if isinstance(sanctions, dict) and sanctions.get("flagged", sanctions.get("hit")):
                lists = sanctions.get("lists", sanctions.get("sources", []))
                self.add_finding(
                    "Sanctioned Cryptocurrency Address",
                    Severity.CRITICAL,
                    "Wallet address appears on sanctions or enforcement blacklists. "
                    "Transactions with this address may violate regulatory requirements.",
                    evidence=f"Flagged on: {', '.join(str(l) for l in lists[:5])}" if lists else str(sanctions)[:500],
                    recommendation="Cease all transactions with this address immediately. "
                    "Report to compliance team. File SAR if required.",
                    tags=["crypto", "sanctions", "compliance", "critical-risk"],
                )
            elif isinstance(sanctions, list) and sanctions:
                self.add_finding(
                    "Sanctioned Cryptocurrency Address",
                    Severity.CRITICAL,
                    "Wallet address appears on sanctions or enforcement blacklists.",
                    evidence=str(sanctions)[:500],
                    recommendation="Cease transactions with this address. Report to compliance.",
                    tags=["crypto", "sanctions", "compliance", "critical-risk"],
                )

            # Mixing service detection
            mixing = crypto_data.get("mixing", crypto_data.get("mixer", {}))
            if isinstance(mixing, dict) and mixing.get("detected", mixing.get("involved")):
                services = mixing.get("services", mixing.get("mixers", []))
                self.add_finding(
                    "Cryptocurrency Mixing Service Usage",
                    Severity.HIGH,
                    "Funds have been routed through cryptocurrency mixing/tumbling "
                    "services, a common technique to obscure transaction origins.",
                    evidence=f"Services: {', '.join(str(s) for s in services[:5])}" if services else str(mixing)[:500],
                    recommendation="Flag for AML review. Trace pre-mixer inputs if possible. "
                    "Report suspicious mixing activity to compliance.",
                    tags=["crypto", "mixing", "aml", "laundering"],
                )

            # Suspicious transaction patterns
            patterns = crypto_data.get("suspicious_patterns", crypto_data.get("anomalies", []))
            if isinstance(patterns, list) and patterns:
                self.add_finding(
                    f"Suspicious Transaction Patterns ({len(patterns)})",
                    Severity.HIGH,
                    f"Identified {len(patterns)} suspicious transaction pattern(s): "
                    "rapid movements, round-number transfers, or structuring behavior.",
                    evidence=str(patterns)[:500],
                    recommendation="Conduct detailed transaction graph analysis. "
                    "Correlate with known threat actor wallets.",
                    tags=["crypto", "suspicious-tx", "aml"],
                )

            # Wallet balance and activity
            balance = crypto_data.get("balance", crypto_data.get("wallet_info", {}))
            if isinstance(balance, dict):
                tx_count = balance.get("tx_count", balance.get("transactions", 0))
                total = balance.get("total_received", balance.get("received", ""))
                if tx_count or total:
                    self.add_finding(
                        "Cryptocurrency Wallet Intelligence",
                        Severity.INFO,
                        f"Wallet activity: {tx_count} transaction(s), "
                        f"total received: {total or 'unknown'}.",
                        evidence=str(balance)[:300],
                        tags=["crypto", "wallet", "intelligence"],
                    )

        # CryptoOSINT extended analysis
        cosint_data = data.get("cryptoosint", {})
        if isinstance(cosint_data, dict):
            # Darknet market associations
            darknet = cosint_data.get("darknet", cosint_data.get("market_associations", []))
            if isinstance(darknet, list) and darknet:
                self.add_finding(
                    f"Darknet Market Associations ({len(darknet)})",
                    Severity.CRITICAL,
                    f"Wallet address linked to {len(darknet)} darknet marketplace(s). "
                    "Strong indicator of illicit activity.",
                    evidence=str(darknet)[:500],
                    recommendation="Report to law enforcement. Block associated addresses. "
                    "Conduct full transaction history review.",
                    tags=["crypto", "darknet", "illicit"],
                )

            # Steganography detection
            stego = cosint_data.get("steganography", cosint_data.get("stego", {}))
            if isinstance(stego, dict) and stego.get("detected", stego.get("found")):
                method = stego.get("method", stego.get("technique", "unknown"))
                self.add_finding(
                    "Steganographic Content Detected",
                    Severity.HIGH,
                    f"Hidden data detected in media files using {method} steganography. "
                    "May be used for covert communication or data exfiltration.",
                    evidence=str(stego)[:500],
                    recommendation="Extract and analyze hidden payload. "
                    "Investigate the source and distribution of the media files.",
                    tags=["crypto", "steganography", "covert-comms"],
                )

            # Ransomware wallet linkage
            ransomware = cosint_data.get("ransomware", cosint_data.get("ransom_links", []))
            if isinstance(ransomware, list) and ransomware:
                self.add_finding(
                    f"Ransomware Wallet Linkage ({len(ransomware)})",
                    Severity.CRITICAL,
                    f"Address linked to {len(ransomware)} known ransomware campaign(s).",
                    evidence=str(ransomware)[:500],
                    recommendation="Report to law enforcement immediately. "
                    "Do not transact with this address.",
                    tags=["crypto", "ransomware", "critical-risk"],
                )

        return self.findings

    def handoff(self) -> list[str]:
        has_sanctions_or_suspicious = any(
            f.severity == Severity.CRITICAL or "suspicious" in f.title.lower()
            for f in self.findings
        )
        return ["report-agent"] if has_sanctions_or_suspicious else []
