import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from src.rules.engine import PolicyViolation
from src.analysis.anomaly_detector import AnomalyResult

logger = logging.getLogger(__name__)

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITY_COLOR = {
    "LOW":      "\033[94m",
    "MEDIUM":   "\033[93m",
    "HIGH":     "\033[91m",
    "CRITICAL": "\033[31m",
}
RESET = "\033[0m"


class AlertManager:
    """
    Unified alert dispatcher.
    Outputs: structured console, JSONL log file, optional webhook.
    All timestamps UTC ISO 8601. All output machine-parseable.
    NIST CSF: DE.AE-2 alignment.
    """

    def __init__(
        self,
        log_file: str,
        webhook_url: str | None,
        min_severity: str = "MEDIUM",
        max_log_bytes: int = 10_000_000,
        max_log_backups: int = 3,
    ):
        self._log_file = log_file
        self._webhook_url = webhook_url
        self._min_severity = min_severity
        self._max_log_bytes = max_log_bytes
        self._max_log_backups = max_log_backups
        os.makedirs(
            os.path.dirname(log_file) if os.path.dirname(log_file) else ".",
            exist_ok=True,
        )

    def dispatch_violation(self, violation: PolicyViolation) -> None:
        if SEVERITY_RANK.get(violation.severity, 0) < SEVERITY_RANK.get(self._min_severity, 0):
            return
        alert = self._build_alert(
            alert_type="POLICY_VIOLATION",
            severity=violation.severity,
            device_id=violation.device_id,
            title=f"[{violation.rule_id}] {violation.owasp_category}",
            description=violation.description,
            evidence=violation.evidence,
            remediation=violation.remediation,
            metadata={
                "stride_threat": violation.stride_threat,
                "cve_references": violation.cve_references or [],
            },
        )
        self._output(alert)

    def dispatch_anomaly(self, device_id: str, anomaly: AnomalyResult) -> None:
        if SEVERITY_RANK.get(anomaly.severity, 0) < SEVERITY_RANK.get(self._min_severity, 0):
            return
        alert = self._build_alert(
            alert_type="ANOMALY_DETECTED",
            severity=anomaly.severity,
            device_id=device_id,
            title=f"Behavioral anomaly on field '{anomaly.field}'",
            description=anomaly.description,
            evidence={
                "field": anomaly.field,
                "value": anomaly.value,
                "method": anomaly.method,
                "score": anomaly.score,
            },
            remediation=[
                "Review device logs for the time window around this event.",
                "Cross-reference with other devices on the same network segment.",
                "If anomaly persists, isolate device and perform firmware analysis.",
            ],
        )
        self._output(alert)

    def _build_alert(self, **kwargs) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "framework": "IoTSentinel",
            **kwargs,
        }

    def _output(self, alert: dict[str, Any]) -> None:
        self._console_print(alert)
        self._write_log(alert)
        if self._webhook_url:
            self._send_webhook(alert)

    def _console_print(self, alert: dict[str, Any]) -> None:
        sev = alert.get("severity", "INFO")
        color = SEVERITY_COLOR.get(sev, "")
        logger.critical("%s[%s] %s%s", color + "=" * 60 + RESET, sev, alert["title"], RESET)
        logger.critical("  Time     : %s", alert["timestamp"])
        logger.critical("  Device   : %s", alert["device_id"])
        logger.critical("  Type     : %s", alert["alert_type"])
        logger.critical("  Detail   : %s", alert["description"])
        if alert.get("remediation"):
            logger.critical("  Remediation:")
            for step in alert["remediation"]:
                logger.critical("    -> %s", step)
        logger.critical("%s%s%s", color, "=" * 60, RESET)

    def _write_log(self, alert: dict[str, Any]) -> None:
        try:
            self._rotate_log_if_needed()
            with open(self._log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(alert) + "\n")
        except OSError as e:
            logger.error("Failed to write alert log: %s", e)

    def _rotate_log_if_needed(self) -> None:
        try:
            size = os.path.getsize(self._log_file)
        except OSError:
            return
        if size >= self._max_log_bytes:
            self._rotate_log()

    def _rotate_log(self) -> None:
        base = self._log_file
        # Shift existing backups up: .1 → .2, .2 → .3, etc.
        for i in range(self._max_log_backups, 0, -1):
            src = f"{base}.{i}"
            dst = f"{base}.{i + 1}"
            try:
                os.replace(src, dst)
            except OSError:
                pass
        # Current log becomes .1
        try:
            os.replace(base, f"{base}.1")
        except OSError:
            pass

    def _send_webhook(self, alert: dict[str, Any]) -> None:
        if not self._webhook_url:
            return
        parsed = urllib.parse.urlparse(self._webhook_url)
        if parsed.scheme != "https":
            logger.warning(
                "Webhook URL must use HTTPS (got %s). Alert delivery skipped for security.",
                parsed.scheme,
            )
            return
        try:
            data = json.dumps({
                "text": (
                    f"[IoTSentinel] {alert['severity']}: {alert['title']}"
                    f"\nDevice: {alert['device_id']}"
                )
            }).encode("utf-8")
            req = urllib.request.Request(
                self._webhook_url, data=data,
                headers={"Content-Type": "application/json"}, method="POST"
            )
            urllib.request.urlopen(req, timeout=5)  # nosec B310 - scheme validated as HTTPS above
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            logger.warning("Webhook delivery failed: %s", e)
