"""End-to-end ECP/PAOS tests over an in-memory three-party transport.

The tests drive the real ``Entity.send``/``HTTPBase`` path and replace only
``requests.request``. Every HTTP exchange between the ECP client, the IdP
and the SP is recorded, so the evidence shows where the credentials, the
assertion and RelayState each went.
"""

import json

import pytest

from pathutils import dotname

from saml2 import BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2 import ecp_client
from saml2 import element_to_extension_element
from saml2 import saml
from saml2.client import Saml2Client
from saml2.ecp_client import ECPError
from saml2.profile import ecp
from saml2.profile import paos
from saml2.samlp import AuthnRequest
from saml2.samlp import Response
from saml2.schema import soapenv
from saml2.server import Server


IDP_ENTITY_ID = "urn:mace:example.com:saml:roland:idp"
SP_PAOS_ACS = "http://lingon.catalogix.se:8087/paos"
EVIL_ACS = "https://evil.example.org/collect"
IDP_PAOS_SSO = "http://localhost:8088/sso/paos"
SP_PAGE = "http://sp.example.org/page"
RELAY_STATE = "state-123"
ACTOR = "http://schemas.xmlsoap.org/soap/actor/next"
PAOS_MIME = "application/vnd.paos+xml"


class InMemoryResponse:
    def __init__(self, status_code, text, headers=None):
        self.status_code = status_code
        self.text = text
        self.content = text
        self.headers = headers or {}


class ECPTransport:
    """Stands in for ``requests.request`` and serves the SP and the IdP."""

    def __init__(self):
        self.exchanges = []
        self.idp_response_hook = None
        self.sp_request_hook = None
        self.sp = None
        self.idp = None
        self.authenticated = False

    # -- recording -------------------------------------------------------
    def record(self, who, url, method, kwargs):
        headers = dict((k.lower(), v) for k, v in (kwargs.get("headers") or {}).items())
        entry = {
            "who": who,
            "url": url,
            "method": method,
            "content_type": headers.get("content-type"),
            "body": kwargs.get("data") or "",
            "auth": kwargs.get("auth"),
        }
        self.exchanges.append(entry)
        return entry

    # -- requests.request replacement ------------------------------------
    def __call__(self, method, url, **kwargs):
        headers = dict((k.lower(), v) for k, v in (kwargs.get("headers") or {}).items())

        if url == IDP_PAOS_SSO:
            entry = self.record("idp", url, method, kwargs)
            return self.serve_idp(entry)

        if url == SP_PAOS_ACS and PAOS_MIME in (headers.get("content-type") or ""):
            entry = self.record("sp", url, method, kwargs)
            return self.serve_sp_assertion(entry)

        entry = self.record("sp", url, method, kwargs)
        if url == SP_PAGE and not self.authenticated and "PAOS" in str(kwargs.get("headers")):
            entry["phase"] = "initial"
            return self.serve_sp_request(entry)

        entry["phase"] = "final"
        return InMemoryResponse(200, "ok")

    # -- IdP side --------------------------------------------------------
    def serve_idp(self, entry):
        req = self.idp.parse_authn_request(entry["body"], BINDING_SOAP)
        assert req is not None
        assert req.verify()

        entry["request_id"] = req.message.id
        entry["request_destination"] = req.message.destination
        entry["request_acs"] = req.message.assertion_consumer_service_url

        sp_entity_id = req.sender()
        name_id = self.idp.ident.transient_nameid("id12", sp_entity_id)
        _, acs_url = self.idp.pick_binding("assertion_consumer_service", [BINDING_PAOS], entity_id=sp_entity_id)

        if self.idp_response_hook is not None:
            response = self.idp_response_hook(req, acs_url)
        else:
            response = self.idp.create_ecp_authn_request_response(
                acs_url,
                {"surName": "Jeter", "givenName": "Derek", "mail": "derek.jeter@nyy.mlb.com"},
                req.message.id,
                acs_url,
                sp_entity_id,
                name_id=name_id,
                authn={"class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"},
                sign_assertion=False,
                sign_response=False,
            )
        entry["response"] = str(response)
        return InMemoryResponse(200, str(response))

    # -- SP side ---------------------------------------------------------
    def serve_sp_request(self, entry):
        if self.sp_request_hook is not None:
            envelope = self.sp_request_hook()
        else:
            _, envelope = self.sp.create_ecp_authn_request(IDP_ENTITY_ID, relay_state=RELAY_STATE)
        entry["response"] = envelope
        return InMemoryResponse(200, envelope, headers={"Content-Type": PAOS_MIME})

    def serve_sp_assertion(self, entry):
        entry["phase"] = "assertion-delivery"
        respdict = self.sp.parse_soap_message(entry["body"])

        relay = [i for i in respdict["header"] if i.c_tag == "RelayState" and i.c_namespace == ecp.NAMESPACE]
        entry["relay_state"] = relay[0].text if relay else None
        entry["delivered_acs"] = entry["url"]

        parsed = self.sp.parse_authn_request_response(str(respdict["body"]), BINDING_PAOS, None)
        entry["assertion_name_id"] = parsed.name_id.text
        entry["assertion_attributes"] = parsed.ava
        entry["assertion_consumed"] = True
        self.authenticated = True
        return InMemoryResponse(302, "", headers={"Location": entry["url"]})


def make_parties(monkeypatch):
    sp = Saml2Client(config_file=dotname("servera_conf"))
    sp.want_response_signed = False
    idp = Server(config_file=dotname("idp_all_conf"))

    transport = ECPTransport()
    transport.sp = sp
    transport.idp = idp

    # The real HTTPBase.send path stays in place; only the socket is replaced.
    monkeypatch.setattr("saml2.httpbase.requests.request", transport)

    client = ecp_client.Client("user", "password", sp=SP_PAGE)
    client.config = sp.config
    client.metadata = sp.metadata
    return transport, client


def dump(transport):
    return json.dumps(transport.exchanges, indent=2, default=str)


def test_normal_login_binds_request_response_and_reports_evidence(monkeypatch, capsys):
    transport, client = make_parties(monkeypatch)

    response = client.operation(SP_PAGE, IDP_ENTITY_ID, "GET", headers=[])
    assert response.status_code == 200

    assert [e.get("phase") for e in transport.exchanges] == ["initial", None, "assertion-delivery", "final"]
    initial, to_idp, to_sp, final = transport.exchanges

    # Phase 1: SP -> client. No credentials, no chosen destination.
    assert initial["who"] == "sp" and initial["url"] == SP_PAGE
    assert initial["auth"] is None
    parsed_sp = client.parse_soap_message(initial["response"])
    assert isinstance(parsed_sp["body"], AuthnRequest)
    assert len([h for h in parsed_sp["header"] if h.c_tag == "Request" and h.c_namespace == paos.NAMESPACE]) == 1
    assert len([h for h in parsed_sp["header"] if h.c_tag == "Request" and h.c_namespace == ecp.NAMESPACE]) == 1
    relays = [h for h in parsed_sp["header"] if h.c_tag == "RelayState" and h.c_namespace == ecp.NAMESPACE]
    assert len(relays) == 1 and relays[0].text == RELAY_STATE

    # Phase 2: client -> IdP. Credentials appear only here.
    assert to_idp["who"] == "idp" and to_idp["url"] == IDP_PAOS_SSO
    assert to_idp["auth"] == ("user", "password")
    assert to_idp["request_id"] == parsed_sp["body"].id
    assert to_idp["request_destination"] == IDP_PAOS_SSO
    assert to_idp["request_acs"] == SP_PAOS_ACS

    idp_resp = client.parse_soap_message(to_idp["response"])
    assert isinstance(idp_resp["body"], Response)
    assert idp_resp["body"].in_response_to == parsed_sp["body"].id
    ecp_responses = [h for h in idp_resp["header"] if h.c_tag == "Response" and h.c_namespace == ecp.NAMESPACE]
    assert len(ecp_responses) == 1
    assert ecp_responses[0].assertion_consumer_service_url == SP_PAOS_ACS

    # Phase 3: client -> SP. Assertion only to the original consumer.
    assert to_sp["url"] == SP_PAOS_ACS and to_sp["delivered_acs"] == SP_PAOS_ACS
    assert to_sp["auth"] is None
    assert to_sp["content_type"] == PAOS_MIME
    assert to_sp["relay_state"] == RELAY_STATE
    assert to_sp["assertion_consumed"] is True
    assert to_sp["assertion_name_id"]
    assert "Jeter" in str(to_sp["assertion_attributes"])

    # Phase 4: the original page is fetched again, without credentials.
    assert final["url"] == SP_PAGE and final["auth"] is None

    for entry in transport.exchanges:
        if entry.get("auth") is not None:
            assert (entry["who"], entry["url"]) == ("idp", IDP_PAOS_SSO)

    print(dump(transport))
    out = capsys.readouterr().out
    assert IDP_PAOS_SSO in out and SP_PAOS_ACS in out and RELAY_STATE in out


def test_idp_replacing_acs_in_ecp_response_is_rejected(monkeypatch):
    transport, client = make_parties(monkeypatch)

    def evil(req, acs_url):
        return transport.idp.create_ecp_authn_request_response(
            EVIL_ACS,
            {"surName": "Jeter"},
            req.message.id,
            EVIL_ACS,
            req.sender(),
            authn={"class_ref": "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"},
            sign_assertion=False,
            sign_response=False,
        )

    transport.idp_response_hook = evil
    with pytest.raises(ECPError, match="does not match AssertionConsumerServiceURL"):
        client.operation(SP_PAGE, IDP_ENTITY_ID, "GET", headers=[])

    assert not [e for e in transport.exchanges if e.get("phase") == "assertion-delivery"]
    # No assertion was posted; EVIL_ACS was never contacted at all.
    assert not [e for e in transport.exchanges if e["url"] == EVIL_ACS]

    credential_entries = [e for e in transport.exchanges if e.get("auth") is not None]
    assert [(e["who"], e["url"], e["auth"]) for e in credential_entries] == [
        ("idp", IDP_PAOS_SSO, ("user", "password"))
    ]


def test_sp_replacing_acs_in_paos_header_is_rejected(monkeypatch):
    transport, client = make_parties(monkeypatch)

    def evil_sp_request():
        header = soapenv.Header()
        header.extension_elements = [
            element_to_extension_element(
                paos.Request(
                    response_consumer_url=EVIL_ACS,
                    service=ecp_client.SERVICE,
                    must_understand="1",
                    actor=ACTOR,
                )
            ),
            element_to_extension_element(
                ecp.Request(
                    must_understand="1",
                    actor=ACTOR,
                    issuer=saml.Issuer(text="urn:mace:example.com:saml:roland:sp"),
                )
            ),
            element_to_extension_element(ecp.RelayState(must_understand="1", actor=ACTOR, text=RELAY_STATE)),
        ]
        body = soapenv.Body()
        body.extension_elements = [
            element_to_extension_element(
                AuthnRequest(
                    destination=IDP_PAOS_SSO,
                    assertion_consumer_service_url=SP_PAOS_ACS,
                    issuer=saml.Issuer(text="urn:mace:example.com:saml:roland:sp"),
                )
            )
        ]
        return str(soapenv.Envelope(header=header, body=body))

    transport.sp_request_hook = evil_sp_request
    with pytest.raises(ECPError, match="responseConsumerURL"):
        client.operation(SP_PAGE, IDP_ENTITY_ID, "GET", headers=[])

    assert not [e for e in transport.exchanges if e["who"] == "idp"]
    assert not [e for e in transport.exchanges if e["url"] == EVIL_ACS]

    credential_entries = [e for e in transport.exchanges if e.get("auth") is not None]
    assert credential_entries == []


def test_relay_state_is_returned_verbatim_but_not_used_for_routing(monkeypatch):
    transport, client = make_parties(monkeypatch)

    def sp_request_with_evil_relay_state():
        _, envelope = transport.sp.create_ecp_authn_request(IDP_ENTITY_ID, relay_state=EVIL_ACS)
        return envelope

    transport.sp_request_hook = sp_request_with_evil_relay_state
    response = client.operation(SP_PAGE, IDP_ENTITY_ID, "GET", headers=[])
    assert response.status_code == 200

    delivery = [e for e in transport.exchanges if e.get("phase") == "assertion-delivery"][0]
    assert delivery["url"] == SP_PAOS_ACS
    assert delivery["relay_state"] == EVIL_ACS
    assert delivery["auth"] is None
    assert not [e for e in transport.exchanges if e["url"] == EVIL_ACS]


def test_multiple_soap_bodies_are_rejected(monkeypatch):
    _, client = make_parties(monkeypatch)
    envelope = """<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">
      <Header><RelayState xmlns="urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp" \
xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" S:mustUnderstand="1" \
S:actor="http://schemas.xmlsoap.org/soap/actor/next">x</RelayState></Header>
      <Body><AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/></Body>
      <Body><AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"/></Body>
    </Envelope>"""
    with pytest.raises(Exception, match="exactly one SOAP Body"):
        client.parse_soap_message(envelope)


def test_missing_required_headers_are_rejected(monkeypatch):
    _, client = make_parties(monkeypatch)

    body_only = (
        "<Envelope xmlns='http://schemas.xmlsoap.org/soap/envelope/'><Body>"
        "<AuthnRequest xmlns='urn:oasis:names:tc:SAML:2.0:protocol'/></Body></Envelope>"
    )
    respdict = client.parse_soap_message(body_only)
    with pytest.raises(ECPError, match="Missing required SOAP header 'Request'"):
        client.parse_sp_ecp_response(respdict)


def test_duplicate_paos_headers_are_rejected(monkeypatch):
    _, client = make_parties(monkeypatch)

    header = soapenv.Header()
    header.extension_elements = [
        element_to_extension_element(
            paos.Request(
                response_consumer_url=SP_PAOS_ACS,
                service=ecp_client.SERVICE,
                must_understand="1",
                actor=ACTOR,
            )
        ),
        element_to_extension_element(
            paos.Request(
                response_consumer_url=EVIL_ACS,
                service=ecp_client.SERVICE,
                must_understand="1",
                actor=ACTOR,
            )
        ),
    ]
    body = soapenv.Body()
    body.extension_elements = [
        element_to_extension_element(
            AuthnRequest(destination=IDP_PAOS_SSO, assertion_consumer_service_url=SP_PAOS_ACS)
        )
    ]
    respdict = client.parse_soap_message(str(soapenv.Envelope(header=header, body=body)))
    with pytest.raises(ECPError, match="single SOAP header 'Request'"):
        client.parse_sp_ecp_response(respdict)


def test_http_credentials_are_scoped_to_the_idp_origin(monkeypatch):
    """The HTTP layer itself refuses to send Basic auth to another origin."""
    import saml2.httpbase as httpbase

    recorded = []

    def fake_request(method, url, **kwargs):
        recorded.append((url, kwargs.get("auth")))
        return InMemoryResponse(200, "ok")

    monkeypatch.setattr("saml2.httpbase.requests.request", fake_request)
    sender = httpbase.HTTPBase()
    sender.add_credentials("user", "password", allow_urls=[IDP_PAOS_SSO])

    sender.send(SP_PAOS_ACS)
    sender.send("https://evil.example.org/collect")
    sender.send(IDP_PAOS_SSO)

    assert recorded == [
        (SP_PAOS_ACS, None),
        ("https://evil.example.org/collect", None),
        (IDP_PAOS_SSO, ("user", "password")),
    ]


def test_sp_helper_parses_paos_delivery(monkeypatch):
    """The SP-side helper must consume the exact message phase 3 produced."""
    transport, client = make_parties(monkeypatch)
    client.operation(SP_PAGE, IDP_ENTITY_ID, "GET", headers=[])

    delivery = [e for e in transport.exchanges if e.get("phase") == "assertion-delivery"][0]
    response, relay_state = transport.sp.parse_ecp_authn_response(delivery["body"])

    assert response.name_id.text == delivery["assertion_name_id"]
    assert relay_state is not None and relay_state.text == RELAY_STATE
