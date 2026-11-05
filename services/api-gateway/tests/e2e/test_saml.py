"""SAML single sign-on, against a stand-in identity provider that signs real assertions."""
import base64
import copy
import os
import secrets
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient
from lxml import etree
from signxml import XMLSigner

from config import settings

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"
GATEWAY = "https://gateway.example"
ACS = f"{GATEWAY}/api/v1/auth/saml/acs"
SP = f"{GATEWAY}/api/v1/auth/saml/metadata"
IDP = "https://idp.example/saml"
REDIRECT = "https://dashboard.example/sso/callback"
NS = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol", "saml": "urn:oasis:names:tc:SAML:2.0:assertion"}


def key_and_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp.example")])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=365))
                   .sign(key, hashes.SHA256()))
    return key, certificate.public_bytes(serialization.Encoding.PEM).decode()


class IdentityProvider:
    def __init__(self):
        self.key, self.certificate = key_and_certificate()

    def response(self, request_id, email, audience=SP, recipient=ACS, issuer=IDP, minutes=5, sign="assertion", key=None):
        now = datetime.now(timezone.utc)
        t = lambda d: (now + d).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
        assertion_id = "_" + uuid.uuid4().hex
        xml = f"""<samlp:Response xmlns:samlp="{NS['samlp']}" xmlns:saml="{NS['saml']}" ID="_{uuid.uuid4().hex}" Version="2.0" IssueInstant="{t(timedelta())}" Destination="{recipient}" InResponseTo="{request_id}">
  <saml:Issuer>{issuer}</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="{t(timedelta())}">
    <saml:Issuer>{issuer}</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData InResponseTo="{request_id}" Recipient="{recipient}" NotOnOrAfter="{t(timedelta(minutes=minutes))}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{t(timedelta(minutes=-1))}" NotOnOrAfter="{t(timedelta(minutes=minutes))}">
      <saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AttributeStatement>
      <saml:Attribute Name="givenName"><saml:AttributeValue>Sam</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""
        root = etree.fromstring(xml.encode())
        signer = XMLSigner(signature_algorithm="rsa-sha256", digest_algorithm="sha256")
        if sign == "assertion":
            assertion = root.find("saml:Assertion", NS)
            signed = signer.sign(assertion, key=key or self.key, cert=self.certificate, reference_uri=assertion.get("ID"))
            root.replace(assertion, signed)
        elif sign == "response":
            root = signer.sign(root, key=key or self.key, cert=self.certificate, reference_uri=root.get("ID"))
        return root

    @staticmethod
    def encode(root):
        return base64.b64encode(etree.tostring(root)).decode()


@pytest.fixture(scope="module")
def client():
    from app import app

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def idp(monkeypatch):
    from core.services import sso

    monkeypatch.setattr(settings, "GATEWAY_URL", GATEWAY)
    monkeypatch.setattr(settings, "WEBHOOK_ALLOW_PRIVATE_ADDRESSES", True)
    fake = IdentityProvider()
    domain_txt = {}

    def dns(request):
        return httpx.Response(200, json={"Answer": [{"type": 16, "data": f'"{v}"'} for v in domain_txt.get(request.url.params["name"], [])]})

    monkeypatch.setattr(sso, "transport", httpx.MockTransport(dns))
    fake.txt = domain_txt
    return fake


@pytest.fixture
def org(client, idp, monkeypatch):
    monkeypatch.setattr(settings, "REGISTRATION_MODE", "organisation")
    suffix = uuid.uuid4().hex[:8]
    credentials = {"username": f"saml_{suffix}", "password": secrets.token_urlsafe(16)}
    domain = f"saml{suffix}.example"
    client.post(f"{API}/auth/register", json={**credentials, "email": f"admin@{domain}", "organisation": f"Org {suffix}"})
    admin = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data=credentials).json()['access_token']}"}
    saved = client.put(f"{API}/tenants/current/sso", json={"provider": "saml", "idp_entity_id": IDP, "idp_sso_url": "https://idp.example/sso",
                                                           "idp_certificate": idp.certificate, "domains": [domain], "enabled": True,
                                                           "auto_provision": True}, headers=admin)
    assert saved.status_code == 200, saved.text
    assert saved.json()["acs_url"] == ACS and saved.json()["sp_entity_id"] == SP
    record = saved.json()["domains"][0]
    idp.txt[record["record_name"]] = [record["record_value"]]
    assert client.post(f"{API}/tenants/current/sso/domains/{domain}/verify", headers=admin).status_code == 200
    return admin, domain


def start(client, email):
    started = client.post(f"{API}/auth/sso/start", json={"email": email, "redirect_uri": REDIRECT})
    assert started.status_code == 200, started.text
    query = parse_qs(urlparse(started.json()["url"]).query)
    request = zlib.decompress(base64.b64decode(query["SAMLRequest"][0]), -15)
    request_id = etree.fromstring(request).get("ID")
    return request_id, query["RelayState"][0]


def post_back(client, response_xml, relay_state):
    answer = client.post(f"{API}/auth/saml/acs", data={"SAMLResponse": IdentityProvider.encode(response_xml), "RelayState": relay_state},
                         follow_redirects=False)
    assert answer.status_code == 303, answer.text
    return parse_qs(urlparse(answer.headers["location"]).query)


def test_signing_in_with_saml(client, idp, org):
    _, domain = org
    request_id, relay = start(client, f"sam@{domain}")
    back = post_back(client, idp.response(request_id, f"sam@{domain}"), relay)
    assert back["state"] == [relay]
    signed_in = client.post(f"{API}/auth/sso/callback", json={"code": back["code"][0], "state": relay})
    assert signed_in.status_code == 200, signed_in.text
    assert signed_in.json()["user"]["email"] == f"sam@{domain}" and signed_in.json()["user"]["firstName"] == "Sam"
    # The code works once.
    assert client.post(f"{API}/auth/sso/callback", json={"code": back["code"][0], "state": relay}).status_code == 401


def test_a_whole_signed_response_is_accepted(client, idp, org):
    _, domain = org
    request_id, relay = start(client, f"sam@{domain}")
    back = post_back(client, idp.response(request_id, f"sam@{domain}", sign="response"), relay)
    assert "code" in back, back


@pytest.mark.parametrize("problem, expected", [
    ("unsigned", "signature"),
    ("other key", "signature"),
    ("audience", "not for UTDRS"),
    ("recipient", "somewhere else"),
    ("issuer", "not your identity provider"),
    ("expired", "not valid now"),
    ("wrong request", "does not answer this sign-in"),
    ("other domain", "not in one of your organisation"),
])
def test_answers_that_cannot_be_believed(client, idp, org, problem, expected):
    _, domain = org
    request_id, relay = start(client, f"sam@{domain}")
    other_key, _ = key_and_certificate()
    response = {
        "unsigned": lambda: idp.response(request_id, f"sam@{domain}", sign=None),
        "other key": lambda: idp.response(request_id, f"sam@{domain}", key=other_key),
        "audience": lambda: idp.response(request_id, f"sam@{domain}", audience="https://elsewhere.example"),
        "recipient": lambda: idp.response(request_id, f"sam@{domain}", recipient="https://evil.example/acs"),
        "issuer": lambda: idp.response(request_id, f"sam@{domain}", issuer="https://evil.example"),
        "expired": lambda: idp.response(request_id, f"sam@{domain}", minutes=-10),
        "wrong request": lambda: idp.response("_someothersignin", f"sam@{domain}"),
        "other domain": lambda: idp.response(request_id, "mallory@elsewhere.example"),
    }[problem]()
    back = post_back(client, response, relay)
    assert "code" not in back and expected in back["error_description"][0], back


def test_a_signed_assertion_cannot_be_wrapped_around_another(client, idp, org):
    """XML signature wrapping: the signed assertion is kept, and a forged one put where a careless reader looks."""
    _, domain = org
    request_id, relay = start(client, f"sam@{domain}")
    genuine = idp.response(request_id, f"sam@{domain}")
    forged = copy.deepcopy(genuine.find("saml:Assertion", NS))
    for signature in forged.findall("{http://www.w3.org/2000/09/xmldsig#}Signature"):
        forged.remove(signature)
    forged.find("saml:Subject/saml:NameID", NS).text = f"admin@{domain}"
    forged.set("ID", "_forged")
    genuine.insert(2, forged)  # the forged assertion first, the signed one after it
    back = post_back(client, genuine, relay)
    if "code" in back:
        signed_in = client.post(f"{API}/auth/sso/callback", json={"code": back["code"][0], "state": relay}).json()
        assert signed_in["user"]["email"] == f"sam@{domain}"  # never the forged admin
    else:
        assert "error_description" in back


def test_an_answer_cannot_be_used_twice(client, idp, org):
    _, domain = org
    request_id, relay = start(client, f"sam@{domain}")
    response = idp.response(request_id, f"sam@{domain}")
    first = post_back(client, response, relay)
    client.post(f"{API}/auth/sso/callback", json={"code": first["code"][0], "state": relay})
    again = client.post(f"{API}/auth/saml/acs", data={"SAMLResponse": IdentityProvider.encode(response), "RelayState": relay}, follow_redirects=False)
    assert again.status_code == 400


def test_metadata_for_the_identity_provider(client, idp):
    metadata = client.get(f"{API}/auth/saml/metadata")
    assert metadata.status_code == 200 and f'entityID="{SP}"' in metadata.text and f'Location="{ACS}"' in metadata.text
