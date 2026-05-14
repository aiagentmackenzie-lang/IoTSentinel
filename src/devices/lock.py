import random  # nosec B311 - simulation-only, not cryptographic
from .base_device import BaseDevice, DeviceReading


class SmartLock(BaseDevice):
    """
    Simulates a smart lock reporting state and command history.
    STRIDE risk: Replay attacks on unlock commands, PIN disclosure.
    OWASP IoT #7: Insecure Data Transfer.
    """
    STATES = ["locked", "locked", "locked", "unlocked"]

    def read(self) -> DeviceReading:
        return DeviceReading(
            device_id=self.device_id,
            device_type="smart_lock",
            timestamp=self._utc_now(),
            payload={
                "state": random.choice(self.STATES),  # nosec B311
                "last_command": "lock",
                "failed_attempts": random.randint(0, 2),  # nosec B311
                "command_authenticated": True,
                "replay_protection": True,
            },
            protocol="HTTP/CoAP",
            encrypted=True,
            firmware_version=self.firmware_version,
        )

    def simulate_replay_unlock(self) -> DeviceReading:
        """Attack simulation: replay an unlock command with replay_protection disabled.
        STRIDE: Spoofing / Repudiation.
        """
        reading = self.read()
        reading.payload["state"] = "unlocked"
        reading.payload["replay_protection"] = False
        reading.payload["command_authenticated"] = False
        return reading
