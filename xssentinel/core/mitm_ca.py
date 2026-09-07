"""Local CA + per-host leaf certificates for passive HTTPS interception.

PassiveProxy normally CONNECT-tunnels HTTPS untouched (no inspection).  For
operator-approved interception the proxy terminates TLS on the client side
with a per-host certificate signed by a locally generated CA; the operator
installs that CA into their browser/OS and the proxy can then capture HTTPS
parameters exactly like plain HTTP (Phase 50, the documented --passive-mitm
extension).  The flow is modeled on mitmproxy's CA lifecycle.

Layout (``<ca>`` is the combined PEM path the operator passes to the proxy):

    <ca>.pem          CA private key + self-signed CA certificate (auto
                      generated on first use; keep private).
    <ca>-cert.pem     CA certificate ONLY -- this is the file to install
                      into the browser / OS trust store.
    <ca>-leafs/       per-host leaf certificates (key+cert, cached by
                      hostname so repeated CONNECTs don't re-sign).

The optional ``cryptography`` package is required; when it is unavailable
the proxy degrades to blind CONNECT tunneling and :func:`available` returns
False.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import secrets
import threading
from datetime import datetime, timedelta, timezone

_CA_CN = "XSSentinel Proxy CA"
_CA_VALID_DAYS = 3650          # 10 years -- reinstalling a CA is friction
_LEAF_VALID_DAYS = 825         # ~2.25y, under the 825-day Apple cap


def available() -> bool:
    """Whether the optional TLS toolchain is importable."""
    try:
        import cryptography  # noqa: F401
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# cryptography imports are deliberately local: mitm_ca must import cleanly
# (and stay importable) on installs without the optional dependency.
# ---------------------------------------------------------------------------

def _crypto():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    return x509, hashes, serialization, rsa, NameOID


def _cert_only_path(ca_pem_path: str) -> str:
    """The sibling 'installable CA certificate' path for a combined PEM."""
    base, ext = os.path.splitext(ca_pem_path)
    return f"{base}-cert{ext or '.pem'}"


def leaf_cache_dir(ca_pem_path: str) -> str:
    base = os.path.splitext(ca_pem_path)[0]
    return f"{base}-leafs"


def _write_pems(path: str, key_pem: bytes, cert_pem: bytes):
    tmp = f"{path}.tmp-{secrets.token_hex(4)}"
    with open(tmp, "wb") as fh:
        fh.write(key_pem)
        fh.write(cert_pem)
    # Phase 72: key material must not be readable by other local users --
    # the CA key can mint trusted certificates for ANY site.
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass  # best-effort on filesystems without POSIX modes (Windows)
    os.replace(tmp, path)  # atomic: a reader never sees a half-written CA


def generate_ca(ca_pem_path: str) -> None:
    """Create a fresh CA (RSA-2048, 10 years) at ``ca_pem_path`` and write
    the installable certificate to the ``-cert.pem`` sibling.  Idempotent
    callers should check existence first (see :class:`MitmManager`)."""
    x509, hashes, serialization, rsa, NameOID = _crypto()
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_CN)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=_CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False,
            key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(
            key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption())
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    os.makedirs(os.path.dirname(os.path.abspath(ca_pem_path)), exist_ok=True)
    _write_pems(ca_pem_path, key_pem, cert_pem)
    with open(_cert_only_path(ca_pem_path), "wb") as fh:
        fh.write(cert_pem)


class MitmManager:
    """Load-or-create the interception CA and mint per-host leaf certs.

    One instance is shared by the whole proxy (constructed when the operator
    passes ``--mitm-ca``).  Leaf certificates are cached on disk keyed by
    hostname so a busy browser session signs each host once.
    """

    def __init__(self, ca_pem_path: str):
        if not available():
            raise RuntimeError(
                "HTTPS interception needs the optional 'cryptography' "
                "package (pip install cryptography)")
        if not os.path.isfile(ca_pem_path):
            generate_ca(ca_pem_path)
        self.ca_pem_path = os.path.abspath(ca_pem_path)
        self._cache_dir = leaf_cache_dir(self.ca_pem_path)
        # Phase 72: relay threads run concurrently (ThreadingHTTPServer);
        # two threads hitting the same host must not race the on-disk leaf
        # cache into a corrupt interleaved PEM.
        self._leaf_lock = threading.Lock()
        self._load_ca()

    # -- public API ---------------------------------------------------------
    @property
    def cert_only_path(self) -> str:
        """Path of the CA certificate for browser/OS installation."""
        return _cert_only_path(self.ca_pem_path)

    def leaf_cert_path(self, host: str) -> str:
        """Return (creating if needed) a leaf cert path for ``host``.

        ``host`` is a bare hostname / IP literal (no port).  The returned
        file holds the leaf private key + certificate (serverAuth, SAN for
        the host), signed by the local CA.
        """
        digest = hashlib.sha1(host.encode("utf-8", "replace")).hexdigest()
        path = os.path.join(self._cache_dir, f"leaf-{digest}.pem")
        # Phase 72: double-checked lock -- signing under the lock so two
        # relay threads racing the same host cannot interleave writes.
        with self._leaf_lock:
            if os.path.isfile(path):
                return path
            cert, key = self._sign_leaf(host)
            os.makedirs(self._cache_dir, exist_ok=True)
            from cryptography.hazmat.primitives import serialization
            key_pem = key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption())
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            _write_pems(path, key_pem, cert_pem)
            return path

    # -- internals ----------------------------------------------------------
    def _load_ca(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        with open(self.ca_pem_path, "rb") as fh:
            pem = fh.read()
        # Combined PEM: private key + certificate (either order).
        key = serialization.load_pem_private_key(pem, password=None)
        cert = x509.load_pem_x509_certificate(pem)
        self._ca_key = key
        self._ca_cert = cert

    def _sign_leaf(self, host: str):
        x509, hashes, serialization, rsa, NameOID = _crypto()
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        # Hostname or IP literal?
        try:
            ip = ipaddress.ip_address(host)
            san = x509.SubjectAlternativeName([x509.IPAddress(ip)])
        except ValueError:
            san = x509.SubjectAlternativeName([x509.DNSName(host)])
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=_LEAF_VALID_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           True)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False), True)
            .add_extension(san, False)
            .add_extension(x509.ExtendedKeyUsage(
                [x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]), False)  # serverAuth
            .sign(self._ca_key, hashes.SHA256())
        )
        return cert, key
