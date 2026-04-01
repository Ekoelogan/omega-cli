"""AISecurityAgent — AI and machine learning security analysis specialist."""
from __future__ import annotations

from typing import Any

from omega_cli.agents.base_agent import BaseAgent, Finding, Severity


class AISecurityAgent(BaseAgent):
    name = "ai-security-agent"
    description = "AI security analysis — ML model auditing, AI-assisted threat detection"
    category = "ai-security"
    capabilities = ["ai_analysis", "ml_detection", "threat_scoring"]
    tools = ["aisummary", "mldetect"]

    def plan(self) -> list[str]:
        return [
            "Scan for exposed ML model endpoints and APIs",
            "Analyze AI/ML model configurations for misconfigurations",
            "Run AI-assisted threat detection and scoring",
            "Check for model serialization vulnerabilities",
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
        # AI summary / ML endpoint analysis
        ai_data = data.get("aisummary", {})
        if isinstance(ai_data, dict):
            # Exposed ML model endpoints
            endpoints = ai_data.get("endpoints", ai_data.get("ml_apis", []))
            if isinstance(endpoints, list) and endpoints:
                unauthenticated = [
                    ep for ep in endpoints
                    if isinstance(ep, dict) and not ep.get("authenticated", True)
                ]
                if unauthenticated:
                    self.add_finding(
                        f"Unauthenticated ML Endpoints ({len(unauthenticated)})",
                        Severity.CRITICAL,
                        f"Found {len(unauthenticated)} ML model endpoint(s) without authentication. "
                        "Attackers can abuse models for inference, data extraction, or adversarial attacks.",
                        evidence=str(unauthenticated)[:500],
                        recommendation="Add authentication and rate limiting to all ML endpoints. "
                        "Implement API key rotation and access logging.",
                        tags=["ai-security", "ml-endpoint", "unauthenticated"],
                    )
                elif endpoints:
                    self.add_finding(
                        f"ML Model Endpoints Discovered ({len(endpoints)})",
                        Severity.MEDIUM,
                        f"Found {len(endpoints)} ML model API endpoint(s). "
                        "Even authenticated endpoints may be vulnerable to model extraction attacks.",
                        evidence=str(endpoints)[:500],
                        recommendation="Implement query rate limiting and monitor for "
                        "model extraction attempts (high-volume systematic queries).",
                        tags=["ai-security", "ml-endpoint"],
                    )

            # Model serialization vulnerabilities
            models = ai_data.get("models", ai_data.get("model_files", []))
            if isinstance(models, list):
                unsafe_formats = []
                for model in models:
                    if isinstance(model, dict):
                        fmt = str(model.get("format", model.get("type", ""))).lower()
                        name = model.get("name", model.get("file", ""))
                        if fmt in ("pickle", "pkl", "joblib", "h5", "pt"):
                            unsafe_formats.append(f"{name} ({fmt})")
                if unsafe_formats:
                    self.add_finding(
                        f"Unsafe Model Serialization Formats ({len(unsafe_formats)})",
                        Severity.HIGH,
                        "ML models stored in formats vulnerable to deserialization attacks "
                        "(pickle, joblib). Loading untrusted models can lead to code execution.",
                        evidence=", ".join(unsafe_formats[:10]),
                        recommendation="Use safe serialization formats (ONNX, SafeTensors). "
                        "Never load models from untrusted sources without sandboxing.",
                        tags=["ai-security", "deserialization", "rce-risk"],
                    )

            # AI-generated threat summary
            threat_summary = ai_data.get("threat_summary", ai_data.get("analysis", {}))
            if isinstance(threat_summary, dict):
                risk_score = threat_summary.get("risk_score", threat_summary.get("score", 0))
                if isinstance(risk_score, (int, float)) and risk_score > 0:
                    sev = (
                        Severity.CRITICAL if risk_score >= 90 else
                        Severity.HIGH if risk_score >= 70 else
                        Severity.MEDIUM if risk_score >= 40 else
                        Severity.LOW if risk_score >= 20 else
                        Severity.INFO
                    )
                    self.add_finding(
                        f"AI Threat Score: {risk_score}/100",
                        sev,
                        f"AI-assisted threat analysis produced a risk score of {risk_score}/100 "
                        f"for the target.",
                        evidence=str(threat_summary)[:500],
                        recommendation="Investigate findings corresponding to the highest-risk areas. "
                        "Prioritize remediation based on AI-identified attack vectors.",
                        tags=["ai-security", "threat-score"],
                    )

        # ML detection analysis
        ml_data = data.get("mldetect", {})
        if isinstance(ml_data, dict):
            # Adversarial attack detection
            adversarial = ml_data.get("adversarial", ml_data.get("attacks", []))
            if isinstance(adversarial, list) and adversarial:
                self.add_finding(
                    f"Adversarial Attack Vectors ({len(adversarial)})",
                    Severity.HIGH,
                    f"Detected {len(adversarial)} potential adversarial attack vector(s) "
                    "targeting ML models (evasion, poisoning, or model inversion).",
                    evidence=str(adversarial)[:500],
                    recommendation="Implement adversarial training and input validation. "
                    "Deploy model monitoring for distribution drift.",
                    tags=["ai-security", "adversarial", "ml-attack"],
                )

            # Data poisoning indicators
            poisoning = ml_data.get("poisoning", ml_data.get("data_integrity", {}))
            if isinstance(poisoning, dict) and poisoning.get("detected", poisoning.get("suspicious")):
                self.add_finding(
                    "Data Poisoning Indicators",
                    Severity.HIGH,
                    "Indicators of training data poisoning detected. Compromised training "
                    "data can cause models to produce incorrect or biased outputs.",
                    evidence=str(poisoning)[:500],
                    recommendation="Validate training data provenance. Implement data integrity "
                    "checks and outlier detection in training pipelines.",
                    tags=["ai-security", "data-poisoning", "ml-integrity"],
                )

            # Model information leakage
            leakage = ml_data.get("leakage", ml_data.get("information_leak", {}))
            if isinstance(leakage, dict) and leakage.get("detected", leakage.get("vulnerable")):
                leak_type = leakage.get("type", leakage.get("method", "unknown"))
                self.add_finding(
                    f"ML Model Information Leakage ({leak_type})",
                    Severity.MEDIUM,
                    f"Model inference API leaks information via {leak_type}. "
                    "Attackers may reconstruct training data or extract model parameters.",
                    evidence=str(leakage)[:500],
                    recommendation="Reduce prediction confidence granularity. Add differential "
                    "privacy to model outputs. Limit query rates.",
                    tags=["ai-security", "information-leakage", "model-extraction"],
                )

            # Anomaly detection results
            anomalies = ml_data.get("anomalies", ml_data.get("detections", []))
            if isinstance(anomalies, list) and anomalies:
                self.add_finding(
                    f"ML-Detected Anomalies ({len(anomalies)})",
                    Severity.MEDIUM,
                    f"Machine learning analysis flagged {len(anomalies)} behavioral anomaly(ies) "
                    "in the target's traffic or configuration patterns.",
                    evidence=str(anomalies)[:500],
                    recommendation="Investigate flagged anomalies for potential threats. "
                    "Tune detection thresholds based on environment baseline.",
                    tags=["ai-security", "anomaly-detection"],
                )

        return self.findings

    def handoff(self) -> list[str]:
        return ["report-agent"]
