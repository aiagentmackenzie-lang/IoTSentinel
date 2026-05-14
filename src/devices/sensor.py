import random  # nosec B311 - simulation-only, not cryptographic
from .base_device import BaseDevice, DeviceReading


class TemperatureSensor(BaseDevice):
    """
    Simulates a temperature/humidity IoT sensor.
    Normal operating range: 18-28C | 30-70% RH.
    Attack surface: spoofed readings, flooding, insecure MQTT topic.
    STRIDE: Tampering (injected values), Spoofing (fake device ID), DoS (message flood).
    """
    NORMAL_TEMP_RANGE = (18.0, 28.0)
    NORMAL_HUMIDITY_RANGE = (30.0, 70.0)

    def read(self) -> DeviceReading:
        return DeviceReading(
            device_id=self.device_id,
            device_type="temperature_sensor",
            timestamp=self._utc_now(),
            payload={
                "temperature_c": round(random.uniform(*self.NORMAL_TEMP_RANGE), 2),  # nosec B311
                "humidity_pct": round(random.uniform(*self.NORMAL_HUMIDITY_RANGE), 2),  # nosec B311
                "battery_pct": random.randint(20, 100),  # nosec B311
            },
            protocol="MQTT",
            encrypted=True,
            firmware_version=self.firmware_version,
        )

    def simulate_tampered_reading(self) -> DeviceReading:
        """Attack simulation: inject physically impossible values (STRIDE: Tampering)."""
        reading = self.read()
        reading.payload["temperature_c"] = 999.0
        reading.payload["__injected"] = True
        return reading
