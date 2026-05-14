import pytest
from src.analysis.anomaly_detector import BehaviorProfiler

# Realistic baseline temperatures (slight variation around 22C) — stdev ~1.5C
NORMAL_TEMPS = [22.1, 21.8, 22.5, 23.0, 21.3, 22.7, 22.0, 21.5, 23.2, 22.4,
                21.9, 22.8, 21.6, 23.1, 22.3]

# Realistic camera bandwidth baseline (500-2500 KB/s range) — stdev non-zero
NORMAL_BW = [1500.0, 1520.0, 1480.0, 1510.0, 1495.0, 1530.0, 1490.0, 1505.0,
             1515.0, 1485.0, 1525.0, 1500.0, 1510.0, 1490.0, 1505.0]


@pytest.fixture
def profiler():
    return BehaviorProfiler(
        window_size=20,
        zscore_threshold=3.0,
        iqr_multiplier=1.5,
        min_samples=10
    )


def test_no_anomaly_within_normal_range(profiler):
    """Normal sensor readings should not trigger anomalies after baseline is established."""
    device_id = "test-sensor-001"
    results = []
    for temp in NORMAL_TEMPS:
        results = profiler.update_and_analyze(device_id, {"temperature_c": temp})
    # Final reading is within the same normal range — no anomaly expected
    assert all(not r.is_anomaly for r in results)


def test_zscore_detects_extreme_outlier(profiler):
    """A tampered reading of 999C should trigger a CRITICAL Z-score anomaly."""
    device_id = "test-sensor-002"
    # Build a stable varied baseline first (stdev ~0.5C around 22C)
    for temp in NORMAL_TEMPS:
        profiler.update_and_analyze(device_id, {"temperature_c": temp})
    # Inject physically impossible value — z-score will be >> 6 → CRITICAL
    results = profiler.update_and_analyze(device_id, {"temperature_c": 999.0})
    anomalies = [r for r in results if r.is_anomaly and r.method == "zscore"]
    assert len(anomalies) == 1
    assert anomalies[0].severity == "CRITICAL"


def test_insufficient_samples_returns_no_results(profiler):
    """Detection should not fire until min_samples threshold is reached."""
    device_id = "test-sensor-003"
    results = []
    for temp in NORMAL_TEMPS[:3]:   # Only 3 readings — below min_samples=10
        results = profiler.update_and_analyze(device_id, {"temperature_c": temp})
    assert results == []


def test_iqr_detects_network_spike(profiler):
    """IQR should detect an extreme bandwidth spike."""
    device_id = "test-camera-001"
    for bw in NORMAL_BW:
        profiler.update_and_analyze(device_id, {"outbound_kbps": bw})
    # 50000 KB/s is ~33x the normal baseline — extreme IQR outlier
    results = profiler.update_and_analyze(device_id, {"outbound_kbps": 50000.0})
    anomalies = [r for r in results if r.is_anomaly]
    assert len(anomalies) >= 1


def test_baseline_adapts_to_device(profiler):
    """Two devices with different baselines should be evaluated independently."""
    # Device A: normal around 22C | Device B: normal around 50C (industrial environment)
    high_temps = [50.1, 49.8, 50.5, 51.0, 49.3, 50.7, 50.0, 49.5, 51.2, 50.4,
                  49.9, 50.8, 49.6, 51.1, 50.3]
    for t_a, t_b in zip(NORMAL_TEMPS, high_temps):
        profiler.update_and_analyze("device-A", {"temperature_c": t_a})
        profiler.update_and_analyze("device-B", {"temperature_c": t_b})

    # For device A, 50C is ~18 stdevs above its 22C baseline → anomaly
    results_a = profiler.update_and_analyze("device-A", {"temperature_c": 50.0})
    # For device B, 50C is perfectly normal
    results_b = profiler.update_and_analyze("device-B", {"temperature_c": 50.0})

    anomalies_a = [r for r in results_a if r.is_anomaly]
    anomalies_b = [r for r in results_b if r.is_anomaly]

    assert len(anomalies_a) > 0
    assert len(anomalies_b) == 0


def test_constant_baseline_detects_any_deviation():
    """A perfectly stable baseline should still flag a changed value."""
    profiler = BehaviorProfiler(window_size=10, min_samples=3)
    device_id = "stable-sensor"
    for _ in range(3):
        profiler.update_and_analyze(device_id, {"temperature_c": 22.0})

    results = profiler.update_and_analyze(device_id, {"temperature_c": 999.0})

    assert any(result.is_anomaly for result in results)
    assert all(result.score == 9999.0 for result in results)


def test_boolean_payload_fields_are_not_profiled():
    """Discrete boolean state should not be treated as a numeric metric."""
    profiler = BehaviorProfiler(window_size=10, min_samples=3)
    device_id = "camera-boolean"
    for _ in range(3):
        profiler.update_and_analyze(device_id, {"stream_active": True, "outbound_kbps": 1500.0})

    results = profiler.update_and_analyze(
        device_id,
        {"stream_active": False, "outbound_kbps": 1501.0},
    )

    fields = {result.field for result in results}
    assert "stream_active" not in fields
