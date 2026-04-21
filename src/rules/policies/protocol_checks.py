"""
Protocol-level security checks.
"""


def check_plaintext_protocol(protocol: str, device_id: str) -> list[dict]:
    """Check for plaintext/unencrypted protocols."""
    violations = []
    plaintext_protocols = {"HTTP", "MQTT_PLAIN", "TELNET", "FTP"}
    for p in plaintext_protocols:
        if p in protocol.upper():
            violations.append({
                "rule_id": "PROTO-001",
                "description": f"Plaintext protocol detected: {protocol}",
            })
    return violations


def check_deprecated_tls(tls_version: str, device_id: str) -> list[dict]:
    """Flag deprecated TLS versions."""
    violations = []
    deprecated = {"TLS 1.0", "TLS 1.1", "SSL 3.0", "SSL 2.0"}
    if tls_version in deprecated:
        violations.append({
            "rule_id": "PROTO-002",
            "description": f"Deprecated TLS version in use: {tls_version}",
        })
    return violations
