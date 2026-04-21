"""
IoTSentinel CLI - Main entry point.
Usage:
  python -m src.cli.main --mode monitor       # Live monitoring
  python -m src.cli.main --mode attack-demo   # Run attack simulations
  python -m src.cli.main --mode audit         # Single-pass device audit
"""
import argparse
import logging
import sys
from src.config.settings import validate_config
from src.devices.sensor import TemperatureSensor
from src.devices.camera import SmartCamera
from src.devices.lock import SmartLock
from src.monitor.traffic_monitor import TrafficMonitor
from src.analysis.anomaly_detector import BehaviorProfiler
from src.rules.engine import RuleEngine
from src.alerts.alert_manager import AlertManager
from src.attacks.attack_simulator import AttackSimulator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("iotsentinel")

BANNER = r"""
+==========================================+
|         IoTSentinel v1.0.0               |
|  IoT Security Monitoring Framework       |
|  Standards: OWASP IoT | NIST SP 800-213 |
|  Threat Model: STRIDE | MITRE ATT&CK ICS|
+==========================================+
"""


def build_pipeline(detection_cfg, alert_cfg):
    monitor = TrafficMonitor()
    profiler = BehaviorProfiler(
        window_size=detection_cfg.baseline_window,
        zscore_threshold=detection_cfg.zscore_threshold,
        iqr_multiplier=detection_cfg.iqr_multiplier,
        min_samples=detection_cfg.min_samples_required,
    )
    engine = RuleEngine()
    alerts = AlertManager(
        log_file=alert_cfg.log_file,
        webhook_url=alert_cfg.webhook_url,
        min_severity=alert_cfg.min_severity,
    )
    return monitor, profiler, engine, alerts


def run_cycle(reading, monitor, profiler, engine, alerts):
    """Single analysis cycle: monitor -> profile -> rules -> alert."""
    record = monitor.inspect(reading.to_mqtt_topic(), {
        "device_id": reading.device_id,
        "timestamp": reading.timestamp,
        "protocol": reading.protocol,
        "encrypted": reading.encrypted,
        "payload": reading.payload,
    })
    anomalies = profiler.update_and_analyze(reading.device_id, reading.payload)
    violations = engine.evaluate(reading, record)
    for anomaly in anomalies:
        alerts.dispatch_anomaly(reading.device_id, anomaly)
    for violation in violations:
        alerts.dispatch_violation(violation)


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(
        description="IoTSentinel - IoT Security Monitoring Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m src.cli.main --mode monitor --cycles 100
  python -m src.cli.main --mode attack-demo
  python -m src.cli.main --mode audit
        """
    )
    parser.add_argument(
        "--mode",
        choices=["monitor", "attack-demo", "audit"],
        default="monitor",
        help="Operating mode"
    )
    parser.add_argument(
        "--cycles",
        type=int,
        default=50,
        help="Number of telemetry cycles to run (monitor/audit modes)"
    )
    args = parser.parse_args()

    try:
        _, detection_cfg, alert_cfg = validate_config()
    except (EnvironmentError, FileNotFoundError) as e:
        logger.error("Configuration error: %s", e)
        sys.exit(1)

    monitor, profiler, engine, alerts = build_pipeline(detection_cfg, alert_cfg)

    devices = [
        TemperatureSensor(firmware_version="1.0.0"),   # Outdated firmware - triggers I5 rule
        SmartCamera(firmware_version="2.1.3"),
        SmartLock(firmware_version="1.5.0"),
    ]

    logger.info(
        "Starting IoTSentinel in '%s' mode | %d cycles | %d devices",
        args.mode, args.cycles, len(devices)
    )

    if args.mode == "attack-demo":
        attacker = AttackSimulator()
        logger.info("Attack simulation mode active. Injecting adversarial events...")
        attack_readings = [
            attacker.data_exfiltration(devices[1].device_id),
            attacker.lock_brute_force(devices[2].device_id),
            attacker.sensor_tampering(devices[0].device_id),
        ]
        for reading in attack_readings:
            run_cycle(reading, monitor, profiler, engine, alerts)
        logger.info("Attack simulation complete. Check logs/alerts.jsonl for structured output.")

    # Run normal telemetry cycles (always runs, attack-demo adds attacks on top)
    for i in range(args.cycles):
        for device in devices:
            reading = device.read()
            run_cycle(reading, monitor, profiler, engine, alerts)

    logger.info("IoTSentinel run complete.")
    print("\n--- Device Summaries ---")
    for device in devices:
        summary = monitor.get_device_summary(device.device_id)
        logger.info("Device summary: %s", summary)


if __name__ == "__main__":
    main()
