"""
Attack scenario library for IoTSentinel.
Each method simulates a real-world attack pattern documented in MITRE ATT&CK for ICS.
USE ONLY in authorized, isolated lab environments.
"""
import copy
import random
from datetime import datetime, timezone, timedelta
from src.devices.base_device import DeviceReading
from src.devices.camera import SmartCamera
from src.devices.sensor import TemperatureSensor
from src.devices.lock import SmartLock


class AttackSimulator:
    """
    Simulates adversary behavior to validate detection pipeline coverage.

    Scenarios:
      - Mirai-style botnet flood          MITRE ICS T0814: Denial of Service
      - Data exfiltration via camera      MITRE ICS T0830: Adversary-in-the-Middle
      - Smart lock brute-force            MITRE ICS T0812: Default Credentials
      - Sensor value tampering            MITRE ICS T0832: Manipulation of View
      - Replay attack on lock commands    MITRE ICS T0856: Spoof Reporting Message
    """

    def botnet_flood(
        self, device_id: str, burst_count: int = 200, interval_ms: int = 10
    ) -> list[DeviceReading]:
        """
        MITRE ICS T0814: Denial of Service.
        Simulates Mirai-style bot flooding MQTT broker with messages.
        Detection trigger: message rate anomaly on BehaviorProfiler.
        """
        sensor = TemperatureSensor(device_id=device_id)
        readings = []
        base_time = datetime.now(timezone.utc)
        for i in range(burst_count):
            reading = sensor.read()
            # Shift timestamps forward to simulate rapid-fire delivery
            shifted = base_time + timedelta(milliseconds=i * interval_ms)
            reading.timestamp = shifted.isoformat()
            reading.payload["__attack"] = "botnet_flood"
            readings.append(reading)
        return readings

    def data_exfiltration(self, device_id: str) -> DeviceReading:
        """
        MITRE ICS T0830: Adversary-in-the-Middle / Data exfiltration.
        Camera leaks 10x normal bandwidth to an external endpoint.
        Detection trigger: RuleEngine OWASP-I6-002 + IQR anomaly on outbound_kbps.
        """
        camera = SmartCamera(device_id=device_id)
        reading = camera.read()
        reading.payload["outbound_kbps"] = random.uniform(12000, 25000)
        reading.payload["destination_ip"] = "198.51.100.42"  # RFC 5737 test IP
        reading.payload["__attack"] = "data_exfiltration"
        return reading

    def lock_brute_force(self, device_id: str, attempt_count: int = 10) -> DeviceReading:
        """
        MITRE ICS T0812: Default Credentials / Brute force.
        Rapid failed unlock attempts against a smart lock.
        Detection trigger: RuleEngine OWASP-I1-002 (failed_attempts >= 5).
        """
        lock = SmartLock(device_id=device_id)
        reading = lock.read()
        reading.payload["failed_attempts"] = attempt_count
        reading.payload["replay_protection"] = False
        reading.payload["__attack"] = "brute_force"
        return reading

    def sensor_tampering(self, device_id: str) -> DeviceReading:
        """
        MITRE ICS T0832: Manipulation of View.
        Injects physically impossible sensor values.
        Detection trigger: Z-score anomaly on temperature_c.
        """
        sensor = TemperatureSensor(device_id=device_id)
        reading = sensor.simulate_tampered_reading()
        reading.payload["__attack"] = "sensor_tampering"
        return reading

    def replay_attack(self, original_reading: DeviceReading) -> DeviceReading:
        """
        MITRE ICS T0856: Spoof Reporting Message (Replay).
        Rebroadcasts a captured legitimate command with a stale timestamp.
        Detection trigger: timestamp validation in TrafficMonitor.
        """
        replayed = copy.deepcopy(original_reading)
        old_ts = datetime.now(timezone.utc) - timedelta(minutes=10)
        replayed.timestamp = old_ts.isoformat()
        replayed.payload["__attack"] = "replay"
        return replayed
