import random
from .base_device import BaseDevice, DeviceReading


class SmartCamera(BaseDevice):
    """
    Simulates an IP camera producing video stream metadata.
    Normal outbound bandwidth: 500-2500 KB/s (1080p H.264).
    Attack surface: exfiltration via oversized payloads, RTSP auth bypass.
    OWASP IoT #2: Insecure Network Services.
    """
    NORMAL_BANDWIDTH_KBPS = (500, 2500)

    def read(self) -> DeviceReading:
        return DeviceReading(
            device_id=self.device_id,
            device_type="smart_camera",
            timestamp=self._utc_now(),
            payload={
                "stream_active": True,
                "resolution": "1080p",
                "outbound_kbps": round(random.uniform(*self.NORMAL_BANDWIDTH_KBPS), 1),
                "inbound_kbps": round(random.uniform(1, 20), 1),
                "rtsp_auth_enabled": True,
                "tls_enabled": True,
            },
            protocol="RTSP/MQTT",
            encrypted=True,
            firmware_version=self.firmware_version,
        )
