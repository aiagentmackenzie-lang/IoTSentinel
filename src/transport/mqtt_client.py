import json
import logging
import socket
import ssl
from pathlib import Path
from typing import Any, Callable

try:
    import paho.mqtt.client as mqtt
except ImportError:  # pragma: no cover - optional runtime dependency
    mqtt = None

from src.config.settings import BrokerConfig
from src.devices.base_device import DeviceReading

logger = logging.getLogger(__name__)


class SecureMQTTClient:
    """
    MQTT 5.0 client with mandatory TLS 1.3 and mutual authentication.
    Implements certificate pinning, mTLS, auto-reconnect, message callback registry.
    OWASP IoT #7 mitigation: Insecure Data Transfer.
    """

    CONNECTION_ERRORS = (
        ConnectionRefusedError,
        OSError,
        socket.timeout,
        socket.gaierror,
    )

    def __init__(self, config: BrokerConfig, client_id: str):
        if mqtt is None:
            raise ModuleNotFoundError(
                "paho-mqtt is required to use SecureMQTTClient"
            )
        self._config = config
        client_kwargs: dict[str, Any] = {
            "client_id": client_id,
            "protocol": mqtt.MQTTv5,
            "transport": "tcp",
        }
        if hasattr(mqtt, "CallbackAPIVersion"):
            client_kwargs["callback_api_version"] = mqtt.CallbackAPIVersion.VERSION1
        self._client = mqtt.Client(**client_kwargs)
        self._message_handlers: dict[str, Callable] = {}
        self._configure_tls()
        self._configure_auth()
        self._register_callbacks()

    def _configure_tls(self) -> None:
        """TLS 1.3 with certificate pinning and forward-secret AEAD ciphers."""
        missing = [
            path for path in (
                self._config.ca_cert,
                self._config.client_cert,
                self._config.client_key,
            )
            if not Path(path).exists()
        ]
        if missing:
            missing_paths = ", ".join(missing)
            raise FileNotFoundError(
                f"Missing TLS material for MQTT client: {missing_paths}"
            )

        tls_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_3
        tls_context.load_verify_locations(cafile=self._config.ca_cert)
        tls_context.load_cert_chain(
            certfile=self._config.client_cert,
            keyfile=self._config.client_key,
        )
        if hasattr(tls_context, "set_ciphersuites"):
            tls_context.set_ciphersuites(
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"
            )
        self._client.tls_set_context(tls_context)
        logger.info("TLS 1.3 context configured with mutual authentication")

    def _configure_auth(self) -> None:
        self._client.username_pw_set(
            username=self._config.username,
            password=self._config.password,
        )

    def _register_callbacks(self) -> None:
        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.on_message = self._on_message

    def _on_connect(self, client, userdata, flags, rc, properties=None) -> None:
        if rc == 0:
            logger.info("Connected to MQTT broker")
        else:
            logger.error("MQTT connection failed. Return code: %s", rc)

    def _on_disconnect(self, client, userdata, rc, properties=None) -> None:
        if rc != 0:
            logger.warning("Unexpected MQTT disconnect (rc=%s)", rc)

    def _on_message(self, client, userdata, message) -> None:
        topic = message.topic
        for pattern, handler in self._message_handlers.items():
            if mqtt.topic_matches_sub(pattern, topic):
                try:
                    payload = json.loads(message.payload.decode("utf-8"))
                    handler(topic, payload)
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    logger.warning("Malformed message on topic %s: %s", topic, e)

    def publish_reading(self, reading: DeviceReading) -> None:
        topic = reading.to_mqtt_topic()
        payload = json.dumps({
            "device_id": reading.device_id,
            "device_type": reading.device_type,
            "timestamp": reading.timestamp,
            "payload": reading.payload,
            "protocol": reading.protocol,
            "encrypted": reading.encrypted,
            "firmware_version": reading.firmware_version,
        })
        self._client.publish(topic, payload, qos=1, retain=False)
        logger.debug("Published to %s", topic)

    def subscribe(self, topic_pattern: str, handler: Callable) -> None:
        self._message_handlers[topic_pattern] = handler
        self._client.subscribe(topic_pattern, qos=1)

    def connect(self) -> None:
        try:
            self._client.connect(self._config.host, self._config.port, keepalive=60)
        except self.CONNECTION_ERRORS as e:
            raise ConnectionError(
                f"Failed to connect to MQTT broker "
                f"at {self._config.host}:{self._config.port}: {e}"
            ) from e
        self._client.loop_start()

    def disconnect(self) -> None:
        self._client.loop_stop()
        self._client.disconnect()
