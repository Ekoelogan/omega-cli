"""CloudAgent — cloud asset discovery and misconfiguration detection."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class CloudAgent(BaseAgent):
    name = "cloud-agent"
    description = "Cloud infrastructure analysis — S3 buckets, Azure blobs, GCP storage, cloud recon"
    category = "cloud"
    capabilities = ["bucket_discovery", "cloud_enum", "s3_permissions"]
    tools = ["cloud", "buckets"]

    def plan(self) -> list[str]:
        return [
            "Cloud provider detection",
            "S3 bucket enumeration",
            "Azure blob discovery",
            "GCP storage discovery",
            "Cloud misconfiguration check",
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
        # Bucket analysis
        bucket_data = data.get("buckets", data.get("cloud", {}))
        if isinstance(bucket_data, dict):
            buckets = bucket_data.get("buckets", [])
            for bucket in (buckets if isinstance(buckets, list) else []):
                name = bucket.get("name", str(bucket)) if isinstance(bucket, dict) else str(bucket)
                status = bucket.get("status", "unknown") if isinstance(bucket, dict) else "found"
                if status in ("public", "listable", "writable"):
                    self.add_finding(
                        f"Public Cloud Bucket: {name}",
                        Severity.CRITICAL,
                        f"Cloud storage bucket '{name}' is {status}. "
                        "May expose sensitive data.",
                        recommendation="Restrict bucket permissions. Enable server-side encryption.",
                        tags=["cloud", "s3", "public-bucket"],
                    )
                elif status == "exists":
                    self.add_finding(
                        f"Cloud Bucket Found: {name}",
                        Severity.LOW,
                        f"Bucket '{name}' exists (private). Verify access controls.",
                        tags=["cloud", "s3"],
                    )

        return self.findings

    def handoff(self) -> list[str]:
        has_public = any(f.severity == Severity.CRITICAL for f in self.findings)
        return ["vuln-agent"] if has_public else []
