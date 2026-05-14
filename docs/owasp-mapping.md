# OWASP IoT Top 10 Mapping

| # | Vulnerability | IoTSentinel Control | Rule ID |
|---|---|---|---|
| I1 | Weak/Guessable Passwords | Default credential scanner, brute-force detector | OWASP-I1-001, OWASP-I1-002 |
| I2 | Insecure Network Services | Protocol scanner, rate anomaly, payload size | DOS-001, DOS-002, PROTO-001 |
| I3 | Insecure Ecosystem Interfaces | Replay detection, timestamp validation | STRIDE-REPLAY-001 |
| I5 | Use of Insecure/Outdated Components | Firmware version check | OWASP-I5-001 |
| I6 | Insufficient Privacy Protection | PII/bandwidth detector, unknown destination | OWASP-I6-002, NET-001 |
| I7 | Insecure Data Transfer & Storage | TLS enforcement, encryption verification | OWASP-I7-001, OWASP-I7-002 |