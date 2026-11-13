"""In-process test doubles for stateful single logout.

No real identity provider, network socket or port is involved: the SP's
``send`` is replaced by :class:`StubIdPGroup`, which answers SOAP logout
requests in memory, and Redirect binding messages are decoded in memory too.
The stubs let a test decide per-IdP whether the answer succeeds, is denied,
times out, arrives out of order or is simply never sent.
"""
from urllib.parse import parse_qs
from urllib.parse import urlparse

import saml2
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import config
from saml2.client import Saml2Client
from saml2.md import EntitiesDescriptor
from saml2.md import EntityDescriptor
from saml2.md import IDPSSODescriptor
from saml2.md import SingleLogoutService
from saml2.md import SingleSignOnService
from saml2.saml import Issuer
from saml2.saml import NameID
from saml2.samlp import LogoutResponse
from saml2.samlp import Status
from saml2.samlp import StatusCode
from saml2.samlp import logout_request_from_string
from saml2.s_utils import decode_base64_and_inflate
from saml2.s_utils import deflate_and_base64_encode
from saml2.s_utils import instant
from saml2.s_utils import sid
from saml2.s_utils import success_status_factory
from saml2.soap import make_soap_enveloped_saml_thingy
from saml2.soap import parse_soap_enveloped_saml_logout_request
from saml2.time_util import in_a_while
from saml2 import samlp


SP_ENTITY = "https://sp.example/"
IDP_IDS = {
    "A": "https://idp-a.example/",
    "B": "https://idp-b.example/",
    "C": "https://idp-c.example/",
}
IDP_BASES = {
    "https://idp-a.example/": "http://idp-a.example",
    "https://idp-b.example/": "http://idp-b.example",
    "https://idp-c.example/": "http://idp-c.example",
}
NAMEID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"


class DummyHTTPResponse:
    """Mimics the fragment of ``requests.Response`` the SLO code relies on."""

    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


def build_idp_metadata(entity_id, base):
    sso = [SingleSignOnService(binding=BINDING_HTTP_REDIRECT, location=f"{base}/sso")]
    slo = [
        SingleLogoutService(binding=BINDING_SOAP, location=f"{base}/slo/soap"),
        SingleLogoutService(binding=BINDING_HTTP_REDIRECT, location=f"{base}/slo/redirect"),
    ]
    descriptor = IDPSSODescriptor(
        protocol_support_enumeration="urn:oasis:names:tc:SAML:2.0:protocol",
        single_sign_on_service=sso,
        single_logout_service=slo,
    )
    return EntityDescriptor(entity_id=entity_id, idpsso_descriptor=descriptor)


def build_sp_client():
    """An SP configured against the three in-memory IdPs, signing disabled."""
    entities = [build_idp_metadata(eid, base) for eid, base in IDP_BASES.items()]
    metadata_xml = str(EntitiesDescriptor(entity_descriptor=entities))
    sp_config = {
        "entityid": SP_ENTITY,
        "service": {
            "sp": {
                "endpoints": {
                    "single_logout_service": [
                        ("https://sp.example/slo/redirect", BINDING_HTTP_REDIRECT),
                    ],
                },
                "idp": list(IDP_BASES),
            }
        },
        "xmlsec_binary": None,
        "metadata": [
            {"class": "saml2.mdstore.InMemoryMetaData", "metadata": [(metadata_xml,)]}
        ],
    }
    conf = config.SPConfig()
    conf.load(sp_config)
    client = Saml2Client(conf)

    name_id = NameID(text="alice@example.com", format=NAMEID_FORMAT)
    for entity_id in IDP_BASES:
        client.users.add_information_about_person(
            {
                "name_id": name_id,
                "issuer": entity_id,
                "not_on_or_after": in_a_while(minutes=15),
                "ava": {"mail": ["alice@example.com"]},
            }
        )
    return client, name_id


def make_logout_response(request_id, issuer_entity, status_factory=None):
    """Build an unsigned LogoutResponse XML element for *request_id*."""
    issuer = Issuer(text=issuer_entity)
    status = status_factory() if status_factory else success_status_factory()
    response = LogoutResponse(
        id=sid(),
        version=saml2.VERSION,
        issue_instant=instant(),
        destination="",
        in_response_to=request_id,
        issuer=issuer,
        status=status,
    )
    return response


def denied_status_factory():
    nested = StatusCode(value=samlp.STATUS_REQUEST_DENIED)
    return Status(status_code=StatusCode(value=samlp.STATUS_RESPONDER, status_code=nested))


def decode_redirect_request(http_info):
    """Extract the LogoutRequest id and issuer from a Redirect http_info."""
    location = http_info["headers"][0][1]
    query = parse_qs(urlparse(location).query)
    request_xml = decode_base64_and_inflate(query["SAMLRequest"][0])
    request = logout_request_from_string(request_xml)
    return request.id, request.issuer.text


class StubIdPGroup:
    """Replaces ``Saml2Client.send`` and answers for all three IdPs.

    Each entity id gets a behaviour:

    * ``"success"``  - answer SOAP with a matching success response
    * ``"denied"``   - answer SOAP with a RequestDenied status
    * ``"http_500"`` - answer with a non-200 HTTP status
    * ``"timeout"``  - raise a timeout, as if the IdP never answered
    * ``"redirect"`` - never called over SOAP; handled by the browser flow

    Every received request and every produced response is recorded so tests
    can assert on ordering and retries.
    """

    def __init__(self, behaviours=None):
        self.behaviours = behaviours or {}
        self.requests = []
        self.responses = []
        self.soap_locations = {
            f"{base}/slo/soap": entity_id for entity_id, base in IDP_BASES.items()
        }

    def set_behaviour(self, entity_id, behaviour):
        self.behaviours[entity_id] = behaviour

    def __call__(self, url, method="POST", **kwargs):
        entity_id = self.soap_locations.get(url)
        if entity_id is None:
            raise AssertionError(f"Unexpected SOAP call to {url}")

        request_xml = parse_soap_enveloped_saml_logout_request(kwargs["data"])
        request = logout_request_from_string(request_xml)
        self.requests.append(
            {"entity_id": entity_id, "request_id": request.id, "attempt": len(self.requests)}
        )

        behaviour = self.behaviours.get(entity_id, "success")
        if behaviour == "timeout":
            raise TimeoutError(f"IdP {entity_id} did not answer in time")
        if behaviour == "http_500":
            self.responses.append({"entity_id": entity_id, "request_id": request.id, "http": 500})
            return DummyHTTPResponse(500, "internal error")
        if behaviour == "denied":
            element = make_logout_response(request.id, entity_id, denied_status_factory)
        else:
            element = make_logout_response(request.id, entity_id)

        soap_text = str(make_soap_enveloped_saml_thingy(element))
        self.responses.append(
            {"entity_id": entity_id, "request_id": request.id, "behaviour": behaviour}
        )
        return DummyHTTPResponse(200, soap_text)

    def redirect_response(self, request_id, issuer_entity, denied=False,
                          binding=BINDING_HTTP_REDIRECT):
        """Produce the response in the wire format of *binding*.

        The SP parses Redirect/POST LogoutResponses with the same
        ``parse_logout_request_response`` call; for Redirect the wire format
        is the DEFLATE+base64 query parameter, for POST it is the raw XML.
        """
        factory = denied_status_factory if denied else None
        element = make_logout_response(request_id, issuer_entity, factory)
        if binding == BINDING_HTTP_REDIRECT:
            return deflate_and_base64_encode(str(element)).decode("ascii")
        return str(element)
