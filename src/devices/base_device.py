from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import uuid


@dataclass
class DeviceReading:
    device_id: str
    device_type: str
    timestamp: str
    payload: dict[str, Any]
    protocol: str
    encrypted: bool
    firmware_version: str

    def to_mqtt_topic(self) -> str:
        return f"iot/{self.device_type}/{self.device_id}/telemetry"


class BaseDevice(ABC):
    def __init__(self, device_id: str | None = None, firmware_version: str = "1.0.0"):
        self.device_id = device_id or str(uuid.uuid4())
        self.firmware_version = firmware_version

    @abstractmethod
    def read(self) -> DeviceReading:
        ...

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()
