from collections import defaultdict
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class ConnectionRecord:
    source_device_id: str
    destination: str
    protocol: str
    bytes_transferred: int
    packet_count: int
    first_seen: str
    last_seen: str
    tls_verified: bool
    flags: list[str] = field(default_factory=list)


class TrafficMonitor:
    """
    Builds a connection graph from device telemetry messages.
    Tracks: flow metadata, byte volumes, protocol usage, destination reputation.
    Detects: unexpected destinations, protocol downgrade, payload size anomalies.
    """

    EXPECTED_PROTOCOLS = {"MQTT", "RTSP/MQTT", "HTTP/CoAP"}
    MAX_EXPECTED_PAYLOAD_BYTES = 50_000
    MESSAGE_RATE_WINDOW_SECONDS = 1
    MAX_MESSAGES_PER_WINDOW = 20
    MAX_TIMESTAMP_AGE_SECONDS = 300

    def __init__(self):
        self._connections: dict[str, list[ConnectionRecord]] = defaultdict(list)
        self._known_destinations: set[str] = set()
        self._total_bytes: dict[str, int] = defaultdict(int)
        self._message_times: dict[str, deque[datetime]] = defaultdict(deque)
        self._last_device_timestamp: dict[str, datetime] = {}

    def register_known_destination(self, destination: str) -> None:
        self._known_destinations.add(self._normalize_destination(destination))

    def inspect(self, topic: str, message: dict[str, Any]) -> ConnectionRecord:
        device_id = message.get("device_id", "unknown")
        protocol = message.get("protocol", "UNKNOWN")
        payload = message.get("payload", {})
        payload_size = len(json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8"))
        destination = self._extract_destination(topic, message)
        observed_at = datetime.now(timezone.utc)
        now = observed_at.isoformat()
        flags: list[str] = []
        reading_timestamp = self._parse_timestamp(message.get("timestamp"))

        if self._known_destinations and destination not in self._known_destinations:
            flags.append("UNKNOWN_DESTINATION")
            logger.warning("[MONITOR] Device %s communicating to unknown destination: %s",
                           device_id, destination)

        if protocol not in self.EXPECTED_PROTOCOLS:
            flags.append("INSECURE_PROTOCOL")
            logger.warning("[MONITOR] Unexpected protocol: %s on device %s", protocol, device_id)

        if payload_size > self.MAX_EXPECTED_PAYLOAD_BYTES:
            flags.append("OVERSIZED_PAYLOAD")
            logger.warning("[MONITOR] Oversized payload (%d bytes) from device %s",
                           payload_size, device_id)

        if not message.get("encrypted", False):
            flags.append("UNENCRYPTED_TRANSMISSION")
            logger.error("[MONITOR] UNENCRYPTED message from device %s. OWASP IoT #7 violation.",
                         device_id)

        if self._is_replayed_message(device_id, reading_timestamp, observed_at):
            flags.append("REPLAY_DETECTED")
            logger.error("[MONITOR] Replay or stale telemetry detected from device %s", device_id)

        if self._is_rate_anomaly(device_id, observed_at):
            flags.append("MESSAGE_RATE_ANOMALY")
            logger.warning("[MONITOR] Device %s exceeded expected message rate", device_id)

        self._total_bytes[device_id] += payload_size
        record = ConnectionRecord(
            source_device_id=device_id,
            destination=destination,
            protocol=protocol,
            bytes_transferred=payload_size,
            packet_count=1,
            first_seen=now,
            last_seen=now,
            tls_verified=message.get("encrypted", False),
            flags=flags,
        )
        self._connections[device_id].append(record)
        return record

    def get_device_summary(self, device_id: str) -> dict[str, Any]:
        records = self._connections.get(device_id, [])
        return {
            "device_id": device_id,
            "total_messages": len(records),
            "total_bytes": self._total_bytes[device_id],
            "all_flags": list({f for r in records for f in r.flags}),
            "protocols_seen": list({r.protocol for r in records}),
        }

    def _extract_destination(self, topic: str, message: dict[str, Any]) -> str:
        payload = message.get("payload", {})
        for key in ("destination", "destination_host", "destination_ip", "broker_host"):
            if key in message and message[key]:
                return self._normalize_destination(str(message[key]))
            if key in payload and payload[key]:
                return self._normalize_destination(str(payload[key]))

        parts = topic.split("/")
        if len(parts) > 3:
            return self._normalize_destination(f"topic:{parts[0]}/{parts[1]}/{parts[2]}")
        return "unknown"

    @staticmethod
    def _normalize_destination(destination: str) -> str:
        return destination.strip().lower()

    @staticmethod
    def _parse_timestamp(timestamp: Any) -> datetime | None:
        if not timestamp or not isinstance(timestamp, str):
            return None
        normalized = timestamp.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _is_replayed_message(
        self,
        device_id: str,
        reading_timestamp: datetime | None,
        observed_at: datetime,
    ) -> bool:
        if reading_timestamp is None:
            return False

        last_seen = self._last_device_timestamp.get(device_id)

        is_stale = (
            observed_at.timestamp() - reading_timestamp.timestamp()
            > self.MAX_TIMESTAMP_AGE_SECONDS
        )
        is_backwards = last_seen is not None and reading_timestamp <= last_seen
        is_replay = is_stale or is_backwards

        if not is_replay:
            self._last_device_timestamp[device_id] = reading_timestamp

        return is_replay

    def _is_rate_anomaly(self, device_id: str, observed_at: datetime) -> bool:
        timestamps = self._message_times[device_id]
        timestamps.append(observed_at)
        window_start = observed_at.timestamp() - self.MESSAGE_RATE_WINDOW_SECONDS
        while timestamps and timestamps[0].timestamp() < window_start:
            timestamps.popleft()
        return len(timestamps) > self.MAX_MESSAGES_PER_WINDOW
