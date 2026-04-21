from dataclasses import dataclass, field
from typing import Any
from src.devices.base_device import DeviceReading
from src.monitor.traffic_monitor import ConnectionRecord


@dataclass
class PolicyViolation:
    rule_id: str
    owasp_category: str
    stride_threat: str
    severity: str
    device_id: str
    description: str
    evidence: dict[str, Any]
    remediation: list[str]
    cve_references: list[str] = field(default_factory=list)


class RuleEngine:
    """
    Evaluates device readings and traffic records against a policy library.
    Rules mapped to OWASP IoT Top 10 and STRIDE threats.
    """

    def evaluate(
        self,
        reading: DeviceReading,
        record: ConnectionRecord,
    ) -> list[PolicyViolation]:
        violations = []
        violations.extend(self._check_encryption(reading))
        violations.extend(self._check_default_credentials(reading))
        violations.extend(self._check_camera_exfiltration(reading))
        violations.extend(self._check_lock_failed_attempts(reading))
        violations.extend(self._check_firmware_version(reading))
        violations.extend(self._check_unencrypted_flags(record))
        violations.extend(self._check_unknown_destination(record))
        violations.extend(self._check_replay_flags(record))
        violations.extend(self._check_message_rate_flags(record))
        return violations

    def _check_encryption(self, reading: DeviceReading) -> list[PolicyViolation]:
        if not reading.encrypted:
            return [PolicyViolation(
                rule_id="OWASP-I7-001",
                owasp_category="I7: Insecure Data Transfer & Storage",
                stride_threat="Information Disclosure",
                severity="CRITICAL",
                device_id=reading.device_id,
                description="Device is transmitting data without encryption.",
                evidence={"protocol": reading.protocol, "encrypted": False},
                remediation=[
                    "Enforce TLS 1.3 on all device connections.",
                    "Disable plaintext MQTT port 1883; use 8883 exclusively.",
                    "Implement certificate-based mutual authentication (mTLS).",
                ],
                cve_references=["CVE-2020-13849"],
            )]
        return []

    def _check_default_credentials(self, reading: DeviceReading) -> list[PolicyViolation]:
        """OWASP IoT #1: Weak/Guessable Passwords."""
        if reading.payload.get("default_credentials_active", False):
            return [PolicyViolation(
                rule_id="OWASP-I1-001",
                owasp_category="I1: Weak/Guessable Passwords",
                stride_threat="Spoofing",
                severity="CRITICAL",
                device_id=reading.device_id,
                description="Device operating with factory-default credentials.",
                evidence={"default_credentials_active": True},
                remediation=[
                    "Immediately rotate all device credentials.",
                    "Enforce unique credentials per device at provisioning.",
                    "Implement credential rotation policy (90-day maximum lifetime).",
                    "Use a secrets manager (e.g., HashiCorp Vault) for credential storage.",
                ],
                cve_references=["CVE-2021-33044"],
            )]
        return []

    def _check_camera_exfiltration(self, reading: DeviceReading) -> list[PolicyViolation]:
        """Detect abnormal outbound bandwidth suggesting data exfiltration."""
        if reading.device_type != "smart_camera":
            return []
        outbound = reading.payload.get("outbound_kbps", 0)
        if outbound > 5000:
            return [PolicyViolation(
                rule_id="OWASP-I6-002",
                owasp_category="I6: Insufficient Privacy Protection",
                stride_threat="Information Disclosure",
                severity="HIGH",
                device_id=reading.device_id,
                description=(
                    f"Camera outbound bandwidth ({outbound:.0f} KB/s) far exceeds "
                    "normal streaming rate. Possible data exfiltration."
                ),
                evidence={"outbound_kbps": outbound, "threshold_kbps": 5000},
                remediation=[
                    "Immediately isolate device from network.",
                    "Capture and analyze full traffic with Wireshark.",
                    "Review firmware for unauthorized background processes.",
                    "Implement egress bandwidth limits on switch/firewall.",
                ],
                cve_references=["CVE-2022-29889"],
            )]
        return []

    def _check_lock_failed_attempts(self, reading: DeviceReading) -> list[PolicyViolation]:
        """Detect brute-force or replay attacks on smart lock."""
        if reading.device_type != "smart_lock":
            return []
        attempts = reading.payload.get("failed_attempts", 0)
        if attempts >= 5:
            return [PolicyViolation(
                rule_id="OWASP-I1-002",
                owasp_category="I1: Weak/Guessable Passwords",
                stride_threat="Elevation of Privilege",
                severity="HIGH",
                device_id=reading.device_id,
                description=(
                    f"Smart lock reports {attempts} consecutive failed unlock attempts. "
                    "Possible brute-force or replay attack in progress."
                ),
                evidence={"failed_attempts": attempts},
                remediation=[
                    "Implement account lockout after 3 failed attempts.",
                    "Enable replay protection (nonce/timestamp validation).",
                    "Send push notification to owner and require re-authentication.",
                    "Log all attempts with timestamps for forensic review.",
                ],
            )]
        return []

    def _check_firmware_version(self, reading: DeviceReading) -> list[PolicyViolation]:
        """Flag devices running outdated firmware (OWASP IoT #5)."""
        KNOWN_VULNERABLE = {"0.9.1", "1.0.0", "1.0.1"}
        if reading.firmware_version in KNOWN_VULNERABLE:
            return [PolicyViolation(
                rule_id="OWASP-I5-001",
                owasp_category="I5: Use of Insecure/Outdated Components",
                stride_threat="Tampering",
                severity="MEDIUM",
                device_id=reading.device_id,
                description=(
                    f"Device running firmware v{reading.firmware_version} "
                    "which has known vulnerabilities."
                ),
                evidence={"firmware_version": reading.firmware_version},
                remediation=[
                    "Update firmware to the latest stable release immediately.",
                    "Enable automatic firmware updates with signature verification.",
                    "Subscribe to vendor security advisories.",
                    "Implement SBOM (Software Bill of Materials) tracking.",
                ],
            )]
        return []

    def _check_unencrypted_flags(self, record: ConnectionRecord) -> list[PolicyViolation]:
        violations = []
        if "UNENCRYPTED_TRANSMISSION" in record.flags:
            violations.append(PolicyViolation(
                rule_id="OWASP-I7-002",
                owasp_category="I7: Insecure Data Transfer & Storage",
                stride_threat="Information Disclosure",
                severity="CRITICAL",
                device_id=record.source_device_id,
                description="Traffic monitor detected unencrypted data transmission.",
                evidence={"flags": record.flags, "protocol": record.protocol},
                remediation=[
                    "Block all non-TLS traffic at the network edge.",
                    "Audit device firmware for hardcoded HTTP endpoints.",
                    "Use network segmentation (IoT VLAN) to limit blast radius.",
                ],
            ))
        return violations

    def _check_unknown_destination(self, record: ConnectionRecord) -> list[PolicyViolation]:
        if "UNKNOWN_DESTINATION" not in record.flags:
            return []
        return [PolicyViolation(
            rule_id="NET-001",
            owasp_category="I6: Insufficient Privacy Protection",
            stride_threat="Information Disclosure",
            severity="HIGH",
            device_id=record.source_device_id,
            description=f"Telemetry targeted an unapproved destination: {record.destination}",
            evidence={"destination": record.destination, "flags": record.flags},
            remediation=[
                "Block outbound traffic to the destination until it is verified.",
                "Review device configuration for unexpected egress endpoints.",
                "Update the allowlist only after the destination is approved.",
            ],
        )]

    def _check_replay_flags(self, record: ConnectionRecord) -> list[PolicyViolation]:
        if "REPLAY_DETECTED" not in record.flags:
            return []
        return [PolicyViolation(
            rule_id="STRIDE-REPLAY-001",
            owasp_category="I3: Insecure Ecosystem Interfaces",
            stride_threat="Spoofing",
            severity="HIGH",
            device_id=record.source_device_id,
            description="Telemetry timestamp indicates a replayed or stale message.",
            evidence={"flags": record.flags, "destination": record.destination},
            remediation=[
                "Reject stale messages at the broker or ingestion layer.",
                "Require signed nonces or monotonic counters for device telemetry.",
                "Investigate clock drift if the device is legitimate.",
            ],
        )]

    def _check_message_rate_flags(self, record: ConnectionRecord) -> list[PolicyViolation]:
        if "MESSAGE_RATE_ANOMALY" not in record.flags:
            return []
        return [PolicyViolation(
            rule_id="DOS-001",
            owasp_category="I2: Insecure Network Services",
            stride_threat="Denial of Service",
            severity="HIGH",
            device_id=record.source_device_id,
            description="Device exceeded the expected telemetry rate window.",
            evidence={"flags": record.flags, "bytes_transferred": record.bytes_transferred},
            remediation=[
                "Rate-limit telemetry from the device or its network segment.",
                "Investigate the device for malware or retry storms.",
                "Review broker quotas and backpressure settings.",
            ],
        )]
