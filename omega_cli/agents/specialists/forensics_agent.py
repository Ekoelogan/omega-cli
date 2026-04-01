"""ForensicsAgent — digital forensics and evidence analysis specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class ForensicsAgent(BaseAgent):
    name = "forensics-agent"
    description = "Digital forensics — document analysis, image metadata, IOC extraction"
    category = "forensics"
    capabilities = ["doc_analysis", "image_forensics", "ioc_extraction"]
    tools = ["docosint", "imgosint", "ioc"]

    def plan(self) -> list[str]:
        return [
            "Analyze documents for embedded metadata and secrets",
            "Extract EXIF/GPS data from images",
            "Extract indicators of compromise (IOCs)",
            "Correlate forensic evidence across sources",
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
        # Document analysis
        doc_data = data.get("docosint", {})
        if isinstance(doc_data, dict):
            # Check for embedded secrets in documents
            secrets = doc_data.get("secrets", doc_data.get("embedded_data", []))
            if isinstance(secrets, list) and secrets:
                self.add_finding(
                    f"Secrets Found in Documents ({len(secrets)})",
                    Severity.HIGH,
                    f"Found {len(secrets)} embedded secret(s) in document metadata or content — "
                    "may include internal usernames, file paths, or API keys.",
                    evidence=str(secrets)[:500],
                    recommendation="Sanitize documents before publishing. Strip metadata "
                    "with tools like ExifTool or mat2.",
                    tags=["forensics", "documents", "secrets"],
                )

            # Check for author/creator metadata leakage
            authors = doc_data.get("authors", doc_data.get("creator", []))
            if authors:
                author_list = authors if isinstance(authors, list) else [authors]
                self.add_finding(
                    f"Document Author Metadata Leaked ({len(author_list)} identities)",
                    Severity.MEDIUM,
                    "Document metadata exposes author names and software versions, "
                    "which can be used for social engineering or targeted attacks.",
                    evidence=", ".join(str(a) for a in author_list[:10]),
                    recommendation="Remove author metadata before publishing. "
                    "Use document sanitization in publishing workflows.",
                    tags=["forensics", "metadata", "data-leakage"],
                )

            # Check for internal file paths
            paths = doc_data.get("file_paths", doc_data.get("paths", []))
            if isinstance(paths, list) and paths:
                self.add_finding(
                    "Internal File Paths Exposed in Documents",
                    Severity.MEDIUM,
                    "Document metadata contains internal file system paths, "
                    "revealing infrastructure details (OS, directory structure, usernames).",
                    evidence=", ".join(str(p) for p in paths[:5]),
                    recommendation="Strip all metadata before external distribution.",
                    tags=["forensics", "metadata", "information-disclosure"],
                )

        # Image forensics
        img_data = data.get("imgosint", {})
        if isinstance(img_data, dict):
            # GPS coordinates in images
            gps = img_data.get("gps", img_data.get("location", img_data.get("coordinates", {})))
            if gps and gps != {}:
                lat = gps.get("latitude", gps.get("lat", ""))
                lon = gps.get("longitude", gps.get("lon", ""))
                self.add_finding(
                    "GPS Coordinates Found in Image Metadata",
                    Severity.HIGH,
                    "Image EXIF data contains GPS coordinates, potentially revealing "
                    "physical locations of individuals or sensitive facilities.",
                    evidence=f"Latitude: {lat}, Longitude: {lon}" if lat and lon else str(gps)[:300],
                    recommendation="Strip EXIF/GPS data from all images before publishing. "
                    "Disable location services on cameras.",
                    tags=["forensics", "exif", "gps", "privacy"],
                )

            # Camera/device fingerprinting
            device = img_data.get("device", img_data.get("camera", img_data.get("make", "")))
            if device:
                self.add_finding(
                    "Device Fingerprint in Image Metadata",
                    Severity.LOW,
                    f"Image metadata reveals the capture device: {device}. "
                    "Can be used for device correlation across images.",
                    evidence=str(device)[:300],
                    recommendation="Strip EXIF metadata from images before sharing.",
                    tags=["forensics", "exif", "device-fingerprint"],
                )

        # IOC extraction
        ioc_data = data.get("ioc", {})
        if isinstance(ioc_data, dict):
            ioc_types = {
                "ips": ("Suspicious IP Addresses", "IP address IOCs"),
                "domains": ("Suspicious Domains", "Domain IOCs"),
                "hashes": ("Malware Hashes", "File hash IOCs"),
                "urls": ("Suspicious URLs", "URL IOCs"),
                "emails": ("Suspicious Email Addresses", "Email IOCs"),
            }
            for key, (title, desc_prefix) in ioc_types.items():
                indicators = ioc_data.get(key, [])
                if isinstance(indicators, list) and indicators:
                    sev = Severity.HIGH if key in ("hashes", "ips") else Severity.MEDIUM
                    self.add_finding(
                        f"{title} Extracted ({len(indicators)})",
                        sev,
                        f"{desc_prefix}: extracted {len(indicators)} indicator(s) of compromise. "
                        "Cross-reference with threat intelligence feeds.",
                        evidence=", ".join(str(i) for i in indicators[:10]),
                        recommendation="Block identified IOCs in firewalls and SIEM. "
                        "Submit unknown hashes to sandbox for analysis.",
                        tags=["forensics", "ioc", key],
                    )

        return self.findings

    def handoff(self) -> list[str]:
        return ["report-agent"]
