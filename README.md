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

| Layer | Standard | Coverage |
|---|---|---|
| Device simulation | STRIDE | Spoofing, Tampering, DoS, EoP |
| Traffic monitoring | OWASP IoT | I2, I7 |
| Anomaly detection | NIST CSF DE.AE-2 | Z-score + IQR statistical outliers |
| Rule engine | OWASP IoT Top 10 | I1, I5, I6, I7 |
| Attack simulator | MITRE ATT&CK ICS | T0812, T0814, T0830, T0832, T0856 |

## Environment Variables

Copy `.env.example` to `.env` and configure. Never commit `.env`.

## Docker

```bash
docker-compose up
```

Requires a running Mosquitto broker with TLS certs in `certs/`.
See `docker-compose.yml` for details.
