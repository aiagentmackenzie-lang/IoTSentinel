# IoTSentinel — IoT Security Monitoring Framework

> Standards: OWASP IoT Top 10 | NIST SP 800-213 | STRIDE | MITRE ATT&CK for ICS

## Requirements

- Python 3.10+ (code uses PEP 604 union syntax: `str | None`)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt
# or, if you prefer the modern workflow:
pip install -e .

# Run attack simulation demo
python -m src.cli.main --mode attack-demo --cycles 10

# Run monitoring mode
python -m src.cli.main --mode monitor --cycles 100

# Run tests (with coverage)
pytest tests/ -v --tb=short --cov=src --cov-report=term-missing
```

## Architecture

See [docs/architecture.md](docs/architecture.md) for data flow and layer breakdown.

## Threat Coverage

| Layer | Standard | Coverage | Rule IDs |
|---|---|---|---|
| Device simulation | STRIDE | Spoofing, Tampering, DoS, EoP | — |
| Traffic monitoring | OWASP IoT | I2, I6, I7 | UNENCRYPTED_TRANSMISSION, INSECURE_PROTOCOL, OVERSIZED_PAYLOAD, UNKNOWN_DESTINATION, REPLAY_DETECTED, MESSAGE_RATE_ANOMALY |
| Anomaly detection | NIST CSF DE.AE-2 | Z-score + IQR statistical outliers | — |
| Rule engine | OWASP IoT Top 10 | I1, I2, I5, I6, I7 | OWASP-I1-001, I1-002, I5-001, I6-002, I7-001, I7-002, NET-001, DOS-001, DOS-002, PROTO-001, STRIDE-REPLAY-001 |
| Attack simulator | MITRE ATT&CK ICS | T0812, T0814, T0830, T0832, T0856 | — |

## Environment Variables

Copy `.env.example` to `.env` and configure. Never commit `.env`.

| Variable | Default | Description |
|---|---|---|
| `MQTT_BROKER_HOST` | `localhost` | MQTT broker hostname |
| `MQTT_BROKER_PORT` | `8883` | MQTT broker port (TLS) |
| `MQTT_USERNAME` | `iotsentinel_monitor` | MQTT auth username |
| `MQTT_PASSWORD` | `changeme` | MQTT auth password (**must change for production**) |
| `MQTT_CA_CERT` | `certs/ca.crt` | CA certificate path |
| `MQTT_CLIENT_CERT` | `certs/client.crt` | Client certificate path |
| `MQTT_CLIENT_KEY` | `certs/client.key` | Client private key path |
| `ZSCORE_THRESHOLD` | `3.0` | Z-score anomaly threshold |
| `IQR_MULTIPLIER` | `1.5` | IQR fence multiplier |
| `BASELINE_WINDOW` | `60` | Baseline sample window size |
| `MIN_SAMPLES` | `10` | Minimum samples before detection |
| `ALERT_LOG_FILE` | `logs/alerts.jsonl` | Alert log output path |
| `MIN_ALERT_SEVERITY` | `MEDIUM` | Minimum severity to alert (LOW/MEDIUM/HIGH/CRITICAL) |
| `ALERT_WEBHOOK_URL` | — | HTTPS-only webhook URL for alert delivery |

## Docker

```bash
docker-compose up
```

Includes a Mosquitto broker with TLS 1.3 + mTLS configured on port 8883.
See `mosquitto.conf` for broker configuration and `docker-compose.yml` for service details.