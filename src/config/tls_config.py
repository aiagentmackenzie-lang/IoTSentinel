import ssl
from src.config.settings import BrokerConfig


def build_tls_context(config: BrokerConfig) -> ssl.SSLContext:
    """Build a TLS 1.3 context with mutual authentication."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=config.ca_cert)
    ctx.load_cert_chain(certfile=config.client_cert, keyfile=config.client_key)
    ctx.set_ciphers("TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256")
    return ctx
