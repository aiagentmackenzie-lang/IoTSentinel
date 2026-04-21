from datetime import datetime, timedelta, timezone

from src.devices.sensor import TemperatureSensor
from src.monitor.traffic_monitor import TrafficMonitor


def test_destination_comes_from_payload_endpoint():
    monitor = TrafficMonitor()
    monitor.register_known_destination("198.51.100.42")

    record = monitor.inspect(
        "iot/smart_camera/cam-1/telemetry",
        {
            "device_id": "cam-1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "protocol": "RTSP/MQTT",
            "encrypted": True,
            "payload": {"destination_ip": "198.51.100.42"},
        },
    )

    assert record.destination == "198.51.100.42"
    assert "UNKNOWN_DESTINATION" not in record.flags


def test_stale_timestamp_sets_replay_flag():
    monitor = TrafficMonitor()
    stale_timestamp = datetime.now(timezone.utc) - timedelta(minutes=10)

    record = monitor.inspect(
        "iot/temperature_sensor/sensor-1/telemetry",
        {
            "device_id": "sensor-1",
            "timestamp": stale_timestamp.isoformat(),
            "protocol": "MQTT",
            "encrypted": True,
            "payload": {"temperature_c": 22.0},
        },
    )

    assert "REPLAY_DETECTED" in record.flags


def test_high_message_rate_sets_rate_anomaly_flag():
    monitor = TrafficMonitor()
    sensor = TemperatureSensor(device_id="sensor-flood")
    timestamp = datetime.now(timezone.utc).isoformat()
    flags = set()

    for _ in range(monitor.MAX_MESSAGES_PER_WINDOW + 1):
        reading = sensor.read()
        record = monitor.inspect(
            reading.to_mqtt_topic(),
            {
                "device_id": reading.device_id,
                "timestamp": timestamp,
                "protocol": reading.protocol,
                "encrypted": reading.encrypted,
                "payload": reading.payload,
            },
        )
        flags.update(record.flags)

    assert "MESSAGE_RATE_ANOMALY" in flags
