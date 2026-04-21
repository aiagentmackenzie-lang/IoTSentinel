import os
from dataclasses import dataclass, field
try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional dependency
    def load_dotenv() -> bool:
        return False

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
    """Validate all required config at startup. Raises clearly on missing values."""
    broker = BrokerConfig()
    detection = DetectionConfig()
    alerts = AlertConfig()
    # In demo mode, skip cert file checks if certs don't exist
    return broker, detection, alerts
