import base64
import json
import io
from urllib import request as urlrequest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

from pymdoccbor.mdoc.issuer import MdocCborIssuer
from pymdoccbor.tests.micov_data import MICOV_DATA
from pymdoccbor.tests.pkey import PKEY

class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        pass


def fake_urlopen(req):
    body = json.loads(req.data.decode())
    tbs = base64.b64decode(body["tbs"])
    priv = ec.derive_private_key(int.from_bytes(PKEY['D'], 'big'), ec.SECP256R1())
    signature = priv.sign(tbs, ec.ECDSA(hashes.SHA256()))

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
        x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
        priv.public_key()
    ).serial_number(1).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=1)
    ).sign(priv, hashes.SHA256())
    chain = [cert.public_bytes(serialization.Encoding.PEM).decode()]
    resp = json.dumps({"signature": base64.b64encode(signature).decode(), "chain": chain}).encode()
    return FakeResponse(resp)


def test_remote_signing(monkeypatch):
    monkeypatch.setattr(urlrequest, "urlopen", fake_urlopen)
    issuer = MdocCborIssuer(
        alg="ES256",
        signing_service_url="https://example.com/sign",
    )
    issuer.new(
        data=MICOV_DATA,
        doctype="org.micov.medical.1",
        validity={"issuance_date": "2024-12-31", "expiry_date": "2050-12-31"},
    )
    assert issuer.signed
