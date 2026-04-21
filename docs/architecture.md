# IoTSentinel Architecture

## Data Flow
Device -> [TLS Handshake] -> Broker -> TrafficMonitor captures message
       -> BehaviorProfiler updates baseline
       -> RuleEngine evaluates policy
       -> [ANOMALY / VIOLATION] -> AlertManager -> {Console, File, Webhook}

## Layers
1. Device Simulation Layer - TemperatureSensor, SmartCamera, SmartLock
2. Transport Layer - MQTT 5.0 over TLS 1.3 with mTLS
3. Traffic Monitor - Connection graph, protocol analysis, byte tracking
4. Analysis Layer - Z-score + IQR statistical anomaly detection
5. Rule Engine - OWASP IoT Top 10 + STRIDE-mapped policy enforcement
6. Alert System - Structured JSONL, console, optional webhook
