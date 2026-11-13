"""Regression tests for AssertionConsumerService (ACS) selection at the IdP.

An SP registers two ACS endpoints on different bindings (see
metadata_sp_dual_acs.xml):

    index 1: HTTP-POST      https://dual.sp.example.org/acs/post
    index 2: HTTP-Redirect  https://dual.sp.example.org/acs/redirect

Every test runs the full IdP path: parse_authn_request() -> response_args()
(destination determination) -> create_authn_response().  The expectations
below encode explicit trust rules, independent of the implementation:

R1  The response destination is always a URL registered for the SP in the
    IdP's metadata.  A request-supplied AssertionConsumerServiceURL is only
    a *selector* among registered endpoints, never an authority.
R2  AssertionConsumerServiceIndex selects a registered endpoint by index;
    the destination is read from metadata, never from the request.
R3  ProtocolBinding restricts the candidate endpoints to that binding; the
    URL/index must resolve to an endpoint registered under it.
R4  If URL and index are both present they must identify one and the same
    registered endpoint; a conflicting request is rejected before any
    assertion is generated.
R5  With no selector in the request, the IdP falls back to its own
    configured preferred_binding order.  The choice is IdP-controlled and
    deterministic even when the SP registers several endpoints.
R6  A valid signature authenticates the issuer at parse time; it never
    widens the set of allowed destinations.  Metadata remains the trust
    anchor for the destination whether the request is signed or not.
"""
import base64
from unittest import mock

from pytest import raises

from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import SAMLError
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.client import Saml2Client
from saml2.response import IncorrectlySigned
from saml2.server import Server


SP_ENTITY_ID = "urn:mace:example.com:saml:dual:sp"
SSO_POST_ENDPOINT = "http://localhost:8088/sso/post"

ACS_POST_URL = "https://dual.sp.example.org/acs/post"
ACS_REDIRECT_URL = "https://dual.sp.example.org/acs/redirect"
UNREGISTERED_URL = "https://evil.example.org/acs"

AUTHN = {"class_ref": INTERNETPROTOCOLPASSWORD, "authn_auth": "http://www.example.com/login"}
IDENTITY = {"givenName": ["Derek"], "sn": ["Jeter"], "mail": ["derek@nyy.mlb.com"]}

_UNSET = object()


class TestAcsSelection:
    def setup_class(self):
        self.server = Server("idp_conf_dual_acs")
        self.client = Saml2Client(config_file="sp_dual_acs_conf")

    def teardown_class(self):
        self.server.close()

    # ---------------------------------------------------------------
    # helpers

    def _authn_request(self, sign=False, url=_UNSET, index=None, protocol_binding=_UNSET, tamper=False):
        """Build a (optionally signed) AuthnRequest, base64 encoded for POST."""
        kwargs = {}
        if url is not _UNSET:
            kwargs["assertion_consumer_service_url"] = url
        binding = BINDING_HTTP_POST if protocol_binding is _UNSET else protocol_binding
        _req_id, req = self.client.create_authn_request(
            destination=SSO_POST_ENDPOINT, binding=binding, sign=sign, **kwargs
        )
        if sign:
            xml = req
        else:
            if url is _UNSET:
                req.assertion_consumer_service_url = None
            if protocol_binding is _UNSET:
                req.protocol_binding = None
            if index is not None:
                req.assertion_consumer_service_index = index
            xml = str(req)
        if tamper:
            xml = xml.replace("dual.sp.example.org", "tampered.example.org", 1)
        return base64.b64encode(xml.encode()).decode()

    def _parse(self, enc_request):
        return self.server.parse_authn_request(enc_request, BINDING_HTTP_POST)

    def _destination(self, request):
        return self.server.response_args(request.message)

    def _assert_usable_response(self, request, resp_args, expected_destination, expected_binding):
        """Run the flow to its end: a signed assertion for the chosen destination."""
        assert resp_args["destination"] == expected_destination
        assert resp_args["binding"] == expected_binding
        assert resp_args["sp_entity_id"] == SP_ENTITY_ID

        name_id = self.server.ident.transient_nameid(SP_ENTITY_ID, "id12")
        resp = self.server.create_authn_response(
            IDENTITY.copy(),
            resp_args["in_response_to"],
            resp_args["destination"],
            resp_args["sp_entity_id"],
            name_id_policy=resp_args["name_id_policy"],
            name_id=name_id,
            authn=AUTHN,
        )
        assert resp.destination == expected_destination
        assert resp.assertion, "a usable assertion must have been created"

    def _assert_rejected_before_assertion(self, request):
        """Destination determination must fail before any assertion is generated."""
        with mock.patch.object(self.server, "create_authn_response") as create_response:
            with raises(SAMLError):
                self._destination(request)
        assert create_response.call_count == 0

    # ---------------------------------------------------------------
    # R1: request URL is only a selector among registered endpoints

    def test_unsigned_request_registered_post_url(self):
        req = self._parse(self._authn_request(url=ACS_POST_URL))
        resp_args = self._destination(req)
        self._assert_usable_response(req, resp_args, ACS_POST_URL, BINDING_HTTP_POST)

    def test_unsigned_request_registered_redirect_url(self):
        req = self._parse(self._authn_request(url=ACS_REDIRECT_URL))
        resp_args = self._destination(req)
        self._assert_usable_response(req, resp_args, ACS_REDIRECT_URL, BINDING_HTTP_REDIRECT)

    def test_unsigned_request_unregistered_url_rejected(self):
        req = self._parse(self._authn_request(url=UNREGISTERED_URL))
        self._assert_rejected_before_assertion(req)

    # ---------------------------------------------------------------
    # R6: signatures authenticate the issuer, not the destination

    def test_signed_request_registered_url(self):
        req = self._parse(self._authn_request(url=ACS_POST_URL, sign=True))
        resp_args = self._destination(req)
        self._assert_usable_response(req, resp_args, ACS_POST_URL, BINDING_HTTP_POST)

    def test_signed_request_unregistered_url_rejected(self):
        # A valid signature does not authorize an unregistered destination.
        req = self._parse(self._authn_request(url=UNREGISTERED_URL, sign=True))
        self._assert_rejected_before_assertion(req)

    def test_tampered_signature_rejected_at_parse(self):
        with raises(IncorrectlySigned):
            self._parse(self._authn_request(url=ACS_POST_URL, sign=True, tamper=True))

    def test_unsigned_request_rejected_when_signatures_required(self):
        self.server.config.setattr("idp", "want_authn_requests_signed", True)
        try:
            with raises(IncorrectlySigned):
                self._parse(self._authn_request(url=ACS_POST_URL))
        finally:
            self.server.config.setattr("idp", "want_authn_requests_signed", None)

    def test_signed_request_accepted_when_signatures_required(self):
        self.server.config.setattr("idp", "want_authn_requests_signed", True)
        try:
            req = self._parse(self._authn_request(url=ACS_POST_URL, sign=True))
        finally:
            self.server.config.setattr("idp", "want_authn_requests_signed", None)
        resp_args = self._destination(req)
        self._assert_usable_response(req, resp_args, ACS_POST_URL, BINDING_HTTP_POST)

    # ---------------------------------------------------------------
    # R2: the index selects a registered endpoint; destination from metadata

    def test_index_selects_post_endpoint(self):
        req = self._parse(self._authn_request(index="1"))
        resp_args = self._destination(req)
        self._assert_usable_response(req, resp_args, ACS_POST_URL, BINDING_HTTP_POST)

    def test_index_selects_redirect_endpoint(self):
        req = self._parse(self._authn_request(index="2"))
        resp_args = self._destination(req)
        self._assert_usable_response(req, resp_args, ACS_REDIRECT_URL, BINDING_HTTP_REDIRECT)

    def test_unregistered_index_rejected(self):
        req = self._parse(self._authn_request(index="9"))
        self._assert_rejected_before_assertion(req)

    # ---------------------------------------------------------------
    # R5: no selector -> IdP's own preference decides among several endpoints

    def test_no_selector_uses_idp_preferred_binding(self):
        # Two endpoints are registered; the request must not influence the
        # choice.  The IdP's preferred_binding order puts HTTP-POST first.
        req = self._parse(self._authn_request())
        resp_args = self._destination(req)
        self._assert_usable_response(req, resp_args, ACS_POST_URL, BINDING_HTTP_POST)

    # ---------------------------------------------------------------
    # R3: ProtocolBinding restricts the candidate endpoints

    def test_protocol_binding_only_selects_matching_endpoint(self):
        req = self._parse(self._authn_request(protocol_binding=BINDING_HTTP_REDIRECT))
        resp_args = self._destination(req)
        self._assert_usable_response(req, resp_args, ACS_REDIRECT_URL, BINDING_HTTP_REDIRECT)

    def test_url_conflicting_with_protocol_binding_rejected(self):
        # The POST URL is not registered under the Redirect binding.
        req = self._parse(self._authn_request(url=ACS_POST_URL, protocol_binding=BINDING_HTTP_REDIRECT))
        self._assert_rejected_before_assertion(req)

    def test_index_conflicting_with_protocol_binding_rejected(self):
        # Index 1 is registered for POST, not for Redirect.
        req = self._parse(self._authn_request(index="1", protocol_binding=BINDING_HTTP_REDIRECT))
        self._assert_rejected_before_assertion(req)

    # ---------------------------------------------------------------
    # R4: URL and index together must identify the same endpoint

    def test_consistent_url_and_index_accepted(self):
        req = self._parse(self._authn_request(url=ACS_POST_URL, index="1"))
        resp_args = self._destination(req)
        self._assert_usable_response(req, resp_args, ACS_POST_URL, BINDING_HTTP_POST)

    def test_conflicting_url_and_index_rejected(self):
        # URL names the POST endpoint, index names the Redirect endpoint.
        req = self._parse(self._authn_request(url=ACS_POST_URL, index="2"))
        self._assert_rejected_before_assertion(req)
