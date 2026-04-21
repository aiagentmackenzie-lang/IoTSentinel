"""
Behavioral policy checks based on device-type-specific heuristics.
"""


def check_camera_bandwidth(outbound_kbps: float, device_id: str) -> list[dict]:
    """Flag abnormal camera bandwidth suggesting exfiltration."""
    violations = []
    if outbound_kbps > 5000:
        violations.append({
            "rule_id": "BEHAV-CAM-001",
            "description": f"Camera outbound bandwidth {outbound_kbps:.0f} KB/s exceeds threshold.",
        })
    return violations


def check_lock_failed_attempts(failed_attempts: int, device_id: str) -> list[dict]:
    """Flag brute-force attempts on smart lock."""
    violations = []
    if failed_attempts >= 5:
        violations.append({
            "rule_id": "BEHAV-LOCK-001",
            "description": f"Smart lock: {failed_attempts} consecutive failed attempts.",
        })
    return violations
