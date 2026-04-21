import pytest
from src.attacks.attack_simulator import AttackSimulator
from src.devices.sensor import TemperatureSensor


@pytest.fixture
def simulator():
    return AttackSimulator()


def test_data_exfiltration_exceeds_threshold(simulator):
    """Exfiltration attack should produce outbound_kbps > 5000."""
    reading = simulator.data_exfiltration("cam-001")
    assert reading.payload["outbound_kbps"] > 5000
    assert reading.payload["__attack"] == "data_exfiltration"


def test_lock_brute_force_exceeds_threshold(simulator):
    """Brute force attack should produce failed_attempts >= 5."""
    reading = simulator.lock_brute_force("lock-001", attempt_count=10)
    assert reading.payload["failed_attempts"] >= 5
    assert reading.payload["replay_protection"] is False


def test_sensor_tampering_produces_impossible_value(simulator):
    """Tampered sensor reading should contain impossible temperature."""
    reading = simulator.sensor_tampering("sensor-001")
    assert reading.payload["temperature_c"] == 999.0
    assert reading.payload.get("__injected") is True


def test_replay_attack_uses_old_timestamp(simulator):
    """Replay attack should use a timestamp 10 minutes in the past."""
    from datetime import datetime
    sensor = TemperatureSensor(device_id="sensor-001")
    original = sensor.read()
    replayed = simulator.replay_attack(original)
    original_ts = datetime.fromisoformat(original.timestamp)
    replayed_ts = datetime.fromisoformat(replayed.timestamp)
    diff = original_ts - replayed_ts
    assert diff.total_seconds() >= 9 * 60  # At least 9 minutes old


def test_botnet_flood_produces_expected_count(simulator):
    """Botnet flood should produce exactly burst_count readings."""
    readings = simulator.botnet_flood("sensor-flood-001", burst_count=5, interval_ms=1)
    assert len(readings) == 5
    assert all(r.payload.get("__attack") == "botnet_flood" for r in readings)
