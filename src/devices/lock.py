import random
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
                "state": random.choice(self.STATES),
                "last_command": "lock",
                "failed_attempts": random.randint(0, 2),
                "command_authenticated": True,
                "replay_protection": True,
            },
            protocol="HTTP/CoAP",
            encrypted=True,
            firmware_version=self.firmware_version,
        )
