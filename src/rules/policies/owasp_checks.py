"""
OWASP IoT Top 10 policy checks.
Each check maps to a specific OWASP category and returns PolicyViolation objects.
"""
from typing import Any


def check_i1_weak_passwords(device_id: str, payload: dict[str, Any]) -> list[dict]:
    """OWASP I1: Weak/Guessable Passwords."""
    violations = []
    if payload.get("default_credentials_active", False):
        violations.append({
            "rule_id": "OWASP-I1-001",
            "owasp_category": "I1: Weak/Guessable Passwords",
            "description": "Device operating with factory-default credentials.",
        })
    return violations


def check_i7_insecure_transfer(device_id: str, encrypted: bool, protocol: str) -> list[dict]:
    """OWASP I7: Insecure Data Transfer & Storage."""
    violations = []
    if not encrypted:
        violations.append({
            "rule_id": "OWASP-I7-001",
            "owasp_category": "I7: Insecure Data Transfer & Storage",
            "description": "Device transmitting data without encryption.",
        })
    return violations


def check_i5_outdated_components(device_id: str, firmware_version: str) -> list[dict]:
    """OWASP I5: Use of Insecure/Outdated Components."""
    KNOWN_VULNERABLE = {"0.9.1", "1.0.0", "1.0.1"}
    violations = []
    if firmware_version in KNOWN_VULNERABLE:
        violations.append({
            "rule_id": "OWASP-I5-001",
            "owasp_category": "I5: Use of Insecure/Outdated Components",
            "description": f"Device running vulnerable firmware v{firmware_version}.",
        })
    return violations
