#!/usr/bin/env python
"""End to end checks for structured SAML response failures.

The key security property exercised here is that only an authenticated
response can produce a business level status failure. A forged response
that merely copies the status of a genuine one stays a protocol
rejection (signature category) or an untrusted status and can never
drive a login flow downgrade.
"""
import re
from base64 import b64encode

from pathutils import dotname

from saml2 import config
from saml2 import samlp
from saml2.client import Saml2Client
from saml2.failure import FailureCategory
from saml2.response import StatusError
from saml2.response import StatusNoAuthnContext
from saml2.response import StatusNoPassive
from saml2.server import Server
from saml2.sigver import SignatureError
from pytest import raises


BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
OUTSTANDING = {"id1": "http://foo.example.com/service"}
INJECTED_MESSAGE = "please downgrade MFA <script>alert(1)</script>"


def _post_payload(xml_text):
    return b64encode(xml_text.encode("utf-8"))


def _strip_signature(signed_xml):
    forged = re.sub(r"<\w+:Signature.*?</\w+:Signature>", "", signed_xml, count=1, flags=re.S)
    assert "Signature" not in forged
    return forged


class TestStructuredResponseFailures:
    def setup_class(self):
        self.server = Server(dotname("idp_conf"))

        conf = config.SPConfig()
        conf.load_file(dotname("server_conf"))
        self.conf = conf

    def teardown_class(self):
        self.server.close()

    def _client(self, want_response_signed):
        client = Saml2Client(self.conf)
        client.want_assertions_signed = False
        client.want_response_signed = want_response_signed
        return client

    def _error_response(self, status_value, sign):
        return self.server.create_error_response(
            in_response_to="id1",
            destination="http://lingon.catalogix.se:8087/",
            info=(status_value, INJECTED_MESSAGE),
            sign=sign,
        )

    def test_signed_noauthncontext_is_trusted_business_failure(self):
        signed_xml = self._error_response(samlp.STATUS_NO_AUTHN_CONTEXT, sign=True)
        client = self._client(want_response_signed=True)

        with raises(StatusNoAuthnContext) as exc_info:
            client.parse_authn_request_response(_post_payload(signed_xml), BINDING_HTTP_POST, OUTSTANDING)

        failure = exc_info.value.failure
        assert failure is not None
        assert failure.category is FailureCategory.STATUS
        assert failure.trusted is True
        assert failure.is_business_failure is True
        assert failure.public_reason == "unsupported_authn_context"
        # Top level and nested status codes are both preserved.
        assert failure.status_codes == [samlp.STATUS_RESPONDER, samlp.STATUS_NO_AUTHN_CONTEXT]
        assert failure.in_response_to == "id1"
        assert failure.issuer == "urn:mace:example.com:saml:roland:idp"
        assert failure.response_id
        # The raw StatusMessage is never the public reason.
        assert failure.raw_status_message == INJECTED_MESSAGE
        assert failure.public_reason != INJECTED_MESSAGE

    def test_forged_copy_of_signed_status_is_rejected_when_signing_required(self):
        signed_xml = self._error_response(samlp.STATUS_NO_PASSIVE, sign=True)
        forged_xml = _strip_signature(signed_xml)
        client = self._client(want_response_signed=True)

        with raises(SignatureError) as exc_info:
            client.parse_authn_request_response(_post_payload(forged_xml), BINDING_HTTP_POST, OUTSTANDING)

        failure = exc_info.value.failure
        assert failure is not None
        # No authenticated envelope: the copied NoPassive status must not be
        # treated as an IdP reported business condition.
        assert failure.category is FailureCategory.SIGNATURE
        assert failure.trusted is False
        assert failure.is_business_failure is False
        assert failure.public_reason == "untrusted_response"
        assert failure.status_codes == [samlp.STATUS_RESPONDER, samlp.STATUS_NO_PASSIVE]

    def test_forged_status_without_signature_stays_untrusted(self):
        unsigned_response = self._error_response(samlp.STATUS_NO_PASSIVE, sign=False)
        client = self._client(want_response_signed=False)

        with raises(StatusNoPassive) as exc_info:
            client.parse_authn_request_response(
                _post_payload(str(unsigned_response)), BINDING_HTTP_POST, OUTSTANDING
            )

        failure = exc_info.value.failure
        assert failure.category is FailureCategory.STATUS
        assert failure.trusted is False
        # Same exception class as a genuine NoPassive, but the trust flag keeps
        # it out of every business level branch.
        assert failure.is_business_failure is False
        assert failure.public_reason == "passive_login_not_possible"

    def test_signed_nopassive_and_signed_noauthncontext_have_distinct_reasons(self):
        client = self._client(want_response_signed=True)
        for status_value, expected_reason, expected_cls in [
            (samlp.STATUS_NO_PASSIVE, "passive_login_not_possible", StatusNoPassive),
            (samlp.STATUS_NO_AUTHN_CONTEXT, "unsupported_authn_context", StatusNoAuthnContext),
        ]:
            signed_xml = self._error_response(status_value, sign=True)
            with raises(expected_cls) as exc_info:
                client.parse_authn_request_response(_post_payload(signed_xml), BINDING_HTTP_POST, OUTSTANDING)
            failure = exc_info.value.failure
            assert failure.public_reason == expected_reason
            assert failure.is_business_failure is True

    def test_tampered_signed_response_fails_signature_category(self):
        signed_xml = self._error_response(samlp.STATUS_NO_PASSIVE, sign=True)
        # Change the payload but keep the (now stale) signature element.
        tampered_xml = signed_xml.replace(samlp.STATUS_NO_PASSIVE, samlp.STATUS_AUTHN_FAILED)
        assert tampered_xml != signed_xml
        client = self._client(want_response_signed=True)

        with raises(SignatureError) as exc_info:
            client.parse_authn_request_response(_post_payload(tampered_xml), BINDING_HTTP_POST, OUTSTANDING)

        failure = exc_info.value.failure
        assert failure.category is FailureCategory.SIGNATURE
        assert failure.trusted is False
        assert failure.is_business_failure is False
        assert failure.public_reason == "untrusted_response"

    def test_malformed_xml_is_a_malformed_category_rejection(self):
        client = self._client(want_response_signed=False)
        malformed = _post_payload("<samlp:Response><Status>")
        with raises(Exception) as exc_info:
            client.parse_authn_request_response(malformed, BINDING_HTTP_POST, OUTSTANDING)

        failure = exc_info.value.failure
        assert failure is not None
        assert failure.category is FailureCategory.MALFORMED
        assert failure.trusted is False
        assert failure.is_business_failure is False
        assert failure.public_reason == "malformed_response"

    def test_exception_message_never_contains_raw_status_message(self):
        signed_xml = self._error_response(samlp.STATUS_NO_AUTHN_CONTEXT, sign=True)
        client = self._client(want_response_signed=True)
        with raises(StatusError) as exc_info:
            client.parse_authn_request_response(_post_payload(signed_xml), BINDING_HTTP_POST, OUTSTANDING)
        assert INJECTED_MESSAGE not in str(exc_info.value)
