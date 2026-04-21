import pytest
from src.rules.engine import RuleEngine
from src.devices.sensor import TemperatureSensor
from src.devices.camera import SmartCamera
from src.devices.lock import SmartLock
from src.monitor.traffic_monitor import TrafficMonitor


@pytest.fixture
def engine():
    return RuleEngine()


@pytest.fixture
def monitor():
    return TrafficMonitor()


def get_record(monitor, reading):
    return monitor.inspect(reading.to_mqtt_topic(), {
        "device_id": reading.device_id,
        "timestamp": reading.timestamp,
        "protocol": reading.protocol,
        "encrypted": reading.encrypted,
        "payload": reading.payload,
    })


def test_outdated_firmware_triggers_i5(engine, monitor):
    """Firmware v1.0.0 should trigger OWASP-I5-001."""
    sensor = TemperatureSensor(firmware_version="1.0.0")
    reading = sensor.read()
    record = get_record(monitor, reading)
    violations = engine.evaluate(reading, record)
    rule_ids = [v.rule_id for v in violations]
    assert "OWASP-I5-001" in rule_ids


def test_current_firmware_no_i5(engine, monitor):
    """Up-to-date firmware should not trigger I5."""
    sensor = TemperatureSensor(firmware_version="2.5.0")
    reading = sensor.read()
    record = get_record(monitor, reading)
    violations = engine.evaluate(reading, record)
    rule_ids = [v.rule_id for v in violations]
    assert "OWASP-I5-001" not in rule_ids


def test_camera_exfiltration_detected(engine, monitor):
    """Camera with 15000 KB/s outbound should trigger OWASP-I6-002."""
    camera = SmartCamera(firmware_version="2.1.3")
    reading = camera.read()
    reading.payload["outbound_kbps"] = 15000
    record = get_record(monitor, reading)
    violations = engine.evaluate(reading, record)
    rule_ids = [v.rule_id for v in violations]
    assert "OWASP-I6-002" in rule_ids


def test_lock_brute_force_detected(engine, monitor):
    """Smart lock with 10 failed attempts should trigger OWASP-I1-002."""
    lock = SmartLock(firmware_version="1.5.0")
    reading = lock.read()
    reading.payload["failed_attempts"] = 10
    record = get_record(monitor, reading)
    violations = engine.evaluate(reading, record)
    rule_ids = [v.rule_id for v in violations]
    assert "OWASP-I1-002" in rule_ids


def test_encrypted_device_no_i7(engine, monitor):
    """Properly encrypted device should not trigger I7."""
    sensor = TemperatureSensor(firmware_version="2.0.0")
    reading = sensor.read()
    reading.encrypted = True
    record = get_record(monitor, reading)
    violations = engine.evaluate(reading, record)
    rule_ids = [v.rule_id for v in violations]
    assert "OWASP-I7-001" not in rule_ids


def test_replay_flag_generates_violation(engine, monitor):
    """Stale timestamps should surface a replay policy violation."""
    sensor = TemperatureSensor(firmware_version="2.0.0")
    reading = sensor.read()
    reading.timestamp = "2000-01-01T00:00:00+00:00"
    record = get_record(monitor, reading)

    violations = engine.evaluate(reading, record)

    assert "STRIDE-REPLAY-001" in [v.rule_id for v in violations]


def test_message_rate_flag_generates_violation(engine, monitor):
    """Flooded telemetry should surface a DoS-oriented policy violation."""
    sensor = TemperatureSensor(device_id="sensor-flood", firmware_version="2.0.0")
    violations = []

    for _ in range(monitor.MAX_MESSAGES_PER_WINDOW + 1):
        reading = sensor.read()
        record = get_record(monitor, reading)
        violations = engine.evaluate(reading, record)

    assert "DOS-001" in [v.rule_id for v in violations]
