# STRIDE Threat Model

| STRIDE Threat | Temperature Sensor | Smart Camera | Smart Lock |
|---|---|---|---|
| Spoofing | Fake device ID on broker | Impersonating feed endpoint | Cloned device certificate |
| Tampering | Injected false readings | Modified RTSP frames | Firmware rollback attack |
| Repudiation | No audit log on device | Deleted access footage | No command acknowledgment |
| Information Disclosure | Plaintext MQTT publish | Unencrypted video stream | PIN transmission in clear |
| Denial of Service | Flood broker with messages | Bandwidth exhaustion | Lock command replay/jam |
| Elevation of Privilege | Default credentials | RTSP auth bypass | Admin API without token |

Each threat maps to a specific rule in the RuleEngine and a detection signature in the BehaviorProfiler.
