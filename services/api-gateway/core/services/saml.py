"""
SAML 2.0 single sign-on, for identity providers that offer SAML rather than OpenID Connect
(ADFS, older Okta and OneLogin set-ups, many others). core/services/sso.py holds an
organisation's set-up and its proven domains; this module speaks the protocol.

UTDRS is the service provider. Its entity id is SP_ENTITY_PATH on the gateway, and the
identity provider posts its answers to the assertion consumer service (ACS_PATH). Signing
in: an AuthnRequest goes to the provider (HTTP-Redirect binding); the provider posts back a
Response (HTTP-POST binding). The Response is only believed when:

- it is a success, and its signature (on the Response or the Assertion) is valid for the
  provider's certificate, which is pinned: no other key is accepted, SHA-1 is refused, and
  only the element the signature covers is read, so a signed assertion cannot be wrapped
  around an unsigned one (XML signature wrapping);
- its issuer is the provider, its audience is UTDRS, its recipient and destination are the
  ACS, it is within its validity times, and it answers the request UTDRS sent (InResponseTo),
  so it cannot be replayed or used for another sign-in.

Encrypted assertions are not supported: the identity provider must send them signed and unencrypted
(over HTTPS).
"""
import base64
import secrets
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlencode

from cryptography import x509
from lxml import etree
from signxml import InvalidInput, InvalidSignature, XMLVerifier
from signxml.exceptions import InvalidCertificate, InvalidDigest

from config import settings
from utils.time import utcnow

SP_ENTITY_PATH = "/auth/saml/metadata"
ACS_PATH = "/auth/saml/acs"
CLOCK_SKEW = timedelta(minutes=3)
NS = {"samlp": "urn:oasis:names:tc:SAML:2.0:protocol", "saml": "urn:oasis:names:tc:SAML:2.0:assertion"}
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
EMAIL_ATTRIBUTES = (
    "email", "mail", "emailaddress", "Email", "EmailAddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
)


class SamlError(ValueError):
    """The SAML answer cannot be believed; the message says why, for people."""


def gateway_url() -> str:
    """The gateway's public address, which identity providers reach (GATEWAY_URL)."""
    if not settings.GATEWAY_URL:
        raise SamlError("SAML needs GATEWAY_URL: the gateway's public address, which the identity provider posts to")
    return settings.GATEWAY_URL.rstrip("/") + settings.API_PREFIX


def sp_entity_id() -> str:
    return gateway_url() + SP_ENTITY_PATH


def acs_url() -> str:
    return gateway_url() + ACS_PATH


def metadata() -> str:
    """The service provider's metadata, to give the identity provider."""
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{sp_entity_id()}">'
        '<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>'
        f'<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{acs_url()}" index="0" isDefault="true"/>'
        "</md:SPSSODescriptor></md:EntityDescriptor>"
    )


def load_certificate(pem: str) -> str:
    """The provider's signing certificate, checked to be one, as PEM."""
    text = (pem or "").strip()
    if text and "BEGIN CERTIFICATE" not in text:
        # The bare base64 that metadata files hold.
        text = "-----BEGIN CERTIFICATE-----\n" + "\n".join(text[i:i + 64] for i in range(0, len(text.replace("\n", "")), 64)) + "\n-----END CERTIFICATE-----"
    try:
        certificate = x509.load_pem_x509_certificate(text.encode())
    except ValueError:
        raise SamlError("That is not a certificate: paste the identity provider's signing certificate (PEM)")
    if certificate.not_valid_after_utc < datetime.now(timezone.utc):
        raise SamlError("That certificate has expired")
    return text


def authn_request(config: Dict[str, Any], relay_state: str) -> tuple[str, str]:
    """The URL that sends someone to the provider, and the request's id (to match the answer)."""
    request_id = "_" + secrets.token_hex(20)
    issued = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="{request_id}" Version="2.0" '
        f'IssueInstant="{issued}" Destination="{config["idp_sso_url"]}" AssertionConsumerServiceURL="{acs_url()}" '
        'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
        f"<saml:Issuer>{sp_entity_id()}</saml:Issuer>"
        '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" AllowCreate="true"/>'
        "</samlp:AuthnRequest>"
    )
    deflated = zlib.compress(xml.encode())[2:-4]  # raw DEFLATE, as the Redirect binding wants
    query = urlencode({"SAMLRequest": base64.b64encode(deflated).decode(), "RelayState": relay_state})
    separator = "&" if "?" in config["idp_sso_url"] else "?"
    return f"{config['idp_sso_url']}{separator}{query}", request_id


def _time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise SamlError(f"The answer has an unreadable time: {value}")


def _parse(saml_response: str) -> etree._Element:
    try:
        xml = base64.b64decode(saml_response, validate=False)
    except ValueError:
        raise SamlError("The SAML answer is not readable")
    # No external entities, no network, no huge trees.
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, remove_comments=True)
    try:
        return etree.fromstring(xml, parser=parser)
    except etree.XMLSyntaxError:
        raise SamlError("The SAML answer is not valid XML")


def verify_response(saml_response: str, config: Dict[str, Any], request_id: str) -> Dict[str, Any]:
    """Check a provider's answer (see the module's doc). Returns the email and attributes of who signed in."""
    root = _parse(saml_response)
    if root.tag != f"{{{NS['samlp']}}}Response":
        raise SamlError("That is not a SAML Response")
    status = root.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != SUCCESS:
        raise SamlError(f"The identity provider did not sign you in ({(status.get('Value') if status is not None else 'no status').rsplit(':', 1)[-1]})")
    if root.find("saml:EncryptedAssertion", NS) is not None:
        raise SamlError("Encrypted assertions are not supported: have the identity provider sign them without encrypting")
    destination = root.get("Destination")
    if destination and destination != acs_url():
        raise SamlError("The answer was meant for somewhere else")

    try:
        verified = XMLVerifier().verify(etree.tostring(root), x509_cert=config["idp_certificate"])
    except (InvalidSignature, InvalidDigest, InvalidCertificate, InvalidInput) as e:
        raise SamlError(f"The answer's signature is not valid for your identity provider's certificate: {e}")
    results = verified if isinstance(verified, list) else [verified]
    # Only what the signature covers is read.
    signed = results[0].signed_xml
    if signed.tag == f"{{{NS['saml']}}}Assertion":
        assertion = signed
    elif signed.tag == f"{{{NS['samlp']}}}Response":
        found = signed.findall("saml:Assertion", NS)
        if len(found) != 1:
            raise SamlError("The signed answer must hold exactly one assertion")
        assertion = found[0]
    else:
        raise SamlError("The signature covers neither the answer nor its assertion")

    now = utcnow()
    issuer = assertion.findtext("saml:Issuer", namespaces=NS)
    if (issuer or "").strip() != config["idp_entity_id"]:
        raise SamlError(f"The assertion is from {issuer!r}, not your identity provider")

    conditions = assertion.find("saml:Conditions", NS)
    if conditions is None:
        raise SamlError("The assertion has no conditions (audience and validity)")
    not_before, not_after = _time(conditions.get("NotBefore")), _time(conditions.get("NotOnOrAfter"))
    if (not_before and now + CLOCK_SKEW < not_before) or (not_after and now - CLOCK_SKEW >= not_after):
        raise SamlError("The assertion is not valid now (check the clocks)")
    audiences = [a.text.strip() for a in conditions.findall("saml:AudienceRestriction/saml:Audience", NS) if a.text]
    if sp_entity_id() not in audiences:
        raise SamlError(f"The assertion is not for UTDRS (its audience should be {sp_entity_id()})")

    confirmation = assertion.find("saml:Subject/saml:SubjectConfirmation[@Method='urn:oasis:names:tc:SAML:2.0:cm:bearer']/saml:SubjectConfirmationData", NS)
    if confirmation is None:
        raise SamlError("The assertion has no bearer subject confirmation")
    if confirmation.get("Recipient") != acs_url():
        raise SamlError("The assertion was meant for somewhere else")
    if confirmation.get("InResponseTo") != request_id:
        raise SamlError("The assertion does not answer this sign-in")
    expires = _time(confirmation.get("NotOnOrAfter"))
    if not expires or now - CLOCK_SKEW >= expires:
        raise SamlError("The assertion has expired")

    attributes: Dict[str, Any] = {}
    for attribute in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        values = [v.text for v in attribute.findall("saml:AttributeValue", NS) if v.text]
        if values:
            attributes[attribute.get("Name")] = values[0] if len(values) == 1 else values
    name_id = assertion.find("saml:Subject/saml:NameID", NS)
    email = next((str(attributes[n]) for n in EMAIL_ATTRIBUTES if n in attributes and "@" in str(attributes[n])), None)
    if not email and name_id is not None and "@" in (name_id.text or ""):
        email = name_id.text
    if not email:
        raise SamlError("The identity provider did not say who signed in: send the email address as the NameID or an email attribute")
    given = attributes.get("givenName") or attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")
    family = attributes.get("sn") or attributes.get("surname") or attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname")
    return {
        "email": email.strip().lower(), "sub": (name_id.text if name_id is not None else email),
        "given_name": given if isinstance(given, str) else None, "family_name": family if isinstance(family, str) else None,
        "assertion_id": assertion.get("ID"),
    }
