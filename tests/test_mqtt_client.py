from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.config.settings import BrokerConfig
from src.transport.mqtt_client import SecureMQTTClient


class FakeMQTTClient:
    def __init__(self, *args, **kwargs):
        self.tls_context = None
        self.username = None
        self.password = None
        self.on_connect = None
        self.on_disconnect = None
        self.on_message = None

    def tls_set_context(self, context):
        self.tls_context = context

    def username_pw_set(self, username, password):
        self.username = username
        self.password = password


def test_client_requires_tls_material(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.transport.mqtt_client.mqtt",
        SimpleNamespace(Client=FakeMQTTClient, MQTTv5=object()),
    )

    config = BrokerConfig(
        ca_cert=str(tmp_path / "missing-ca.crt"),
        client_cert=str(tmp_path / "missing-client.crt"),
        client_key=str(tmp_path / "missing-client.key"),
    )

    with pytest.raises(FileNotFoundError):
        SecureMQTTClient(config, client_id="test-client")


def test_client_configures_tls_during_init(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.transport.mqtt_client.mqtt",
        SimpleNamespace(Client=FakeMQTTClient, MQTTv5=object()),
    )

    ca_cert = tmp_path / "ca.crt"
    client_cert = tmp_path / "client.crt"
    client_key = tmp_path / "client.key"
    for path in (ca_cert, client_cert, client_key):
        path.write_text("placeholder", encoding="utf-8")

    fake_context = Mock()
    fake_context.minimum_version = None
    monkeypatch.setattr(
        "src.transport.mqtt_client.ssl.create_default_context",
        Mock(return_value=fake_context),
    )

    config = BrokerConfig(
        ca_cert=str(ca_cert),
        client_cert=str(client_cert),
        client_key=str(client_key),
    )
    client = SecureMQTTClient(config, client_id="test-client")

    assert client._client.tls_context is fake_context
    fake_context.load_verify_locations.assert_called_once_with(cafile=str(ca_cert))
    fake_context.load_cert_chain.assert_called_once_with(
        certfile=str(client_cert),
        keyfile=str(client_key),
    )
