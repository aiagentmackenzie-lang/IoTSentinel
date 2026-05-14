import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    def load_dotenv(**kwargs) -> bool:  # type: ignore[misc]
        return False

logger = logging.getLogger(__name__)

load_dotenv()


@dataclass(frozen=True)
class BrokerConfig:
    host: str = field(default_factory=lambda: os.environ.get("MQTT_BROKER_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(os.getenv("MQTT_BROKER_PORT", "8883")))
    ca_cert: str = field(default_factory=lambda: os.getenv("MQTT_CA_CERT", "certs/ca.crt"))
    client_cert: str = field(default_factory=lambda: os.getenv("MQTT_CLIENT_CERT", "certs/client.crt"))
    client_key: str = field(default_factory=lambda: os.getenv("MQTT_CLIENT_KEY", "certs/client.key"))
    username: str = field(default_factory=lambda: os.getenv("MQTT_USERNAME", "iotsentinel_monitor"))
    password: str = field(default_factory=lambda: os.getenv("MQTT_PASSWORD", "changeme"))


@dataclass(frozen=True)
class DetectionConfig:
    zscore_threshold: float = float(os.getenv("ZSCORE_THRESHOLD", "3.0"))
    iqr_multiplier: float = float(os.getenv("IQR_MULTIPLIER", "1.5"))
    baseline_window: int = int(os.getenv("BASELINE_WINDOW", "60"))
    min_samples_required: int = int(os.getenv("MIN_SAMPLES", "10"))


@dataclass(frozen=True)
class AlertConfig:
    log_file: str = os.getenv("ALERT_LOG_FILE", "logs/alerts.jsonl")
    webhook_url: str | None = os.getenv("ALERT_WEBHOOK_URL")
    min_severity: str = os.getenv("MIN_ALERT_SEVERITY", "MEDIUM")


def validate_config() -> tuple[BrokerConfig, DetectionConfig, AlertConfig]:
    """Validate all required config at startup. Raises clearly on invalid values."""
    broker = BrokerConfig()
    detection = DetectionConfig()
    alerts = AlertConfig()

    # --- Broker validation ---
    if broker.port < 1 or broker.port > 65535:
        raise ValueError(f"MQTT_BROKER_PORT must be 1-65535, got {broker.port}")
    if broker.password == "changeme":  # nosec B105 - default password check, warns at startup
        logger.warning(
            "MQTT_PASSWORD is set to the default value 'changeme'. "
            "This is insecure for production deployments."
        )
    for label, path in [("CA cert", broker.ca_cert),
                        ("client cert", broker.client_cert),
                        ("client key", broker.client_key)]:
        if not Path(path).exists():
            logger.warning(
                "%s not found at %s — TLS connection will fail "
                "(expected in production, OK for demo mode).",
                label, path,
            )

    # --- Detection validation ---
    if detection.zscore_threshold <= 0:
        raise ValueError(f"ZSCORE_THRESHOLD must be positive, got {detection.zscore_threshold}")
    if detection.iqr_multiplier <= 0:
        raise ValueError(f"IQR_MULTIPLIER must be positive, got {detection.iqr_multiplier}")
    if detection.baseline_window < 2:
        raise ValueError(f"BASELINE_WINDOW must be at least 2, got {detection.baseline_window}")
    if detection.min_samples_required < 1:
        raise ValueError(f"MIN_SAMPLES must be at least 1, got {detection.min_samples_required}")

    # --- Alert validation ---
    valid_severities = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    normalized = alerts.min_severity.upper()
    if normalized not in valid_severities:
        raise ValueError(
            f"MIN_ALERT_SEVERITY must be one of {valid_severities}, "
            f"got '{alerts.min_severity}'"
        )
    if alerts.webhook_url and not alerts.webhook_url.startswith("https://"):
        raise ValueError(
            f"ALERT_WEBHOOK_URL must use HTTPS, got '{alerts.webhook_url}'"
        )

    # Rebuild AlertConfig with normalized severity if it differs
    if normalized != alerts.min_severity:
        alerts = AlertConfig(
            log_file=alerts.log_file,
            webhook_url=alerts.webhook_url,
            min_severity=normalized,
        )

    return broker, detection, alerts
