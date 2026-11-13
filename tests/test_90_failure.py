#!/usr/bin/env python
from saml2 import saml
from saml2 import samlp
from saml2.failure import FailureCategory
from saml2.failure import GENERIC_STATUS_REASON
from saml2.failure import MALFORMED_REASON
from saml2.failure import SAMLFailure
from saml2.failure import UNTRUSTED_REASON
from saml2.failure import attach_failure
from saml2.failure import correlation_from_xml
from saml2.failure import failure_from_exception
from saml2.failure import public_reason_for_status
from saml2.failure import status_code_chain
from saml2.failure import status_from_xml


UNSCOPED_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="id-response-1" Version="2.0" IssueInstant="2026-11-13T10:00:00Z"
                InResponseTo="id-request-9">
    <saml:Issuer>https://idp.example.org/</saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
            <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext"/>
        </samlp:StatusCode>
        <samlp:StatusMessage>reflected &lt;script&gt; text</samlp:StatusMessage>
    </samlp:Status>
</samlp:Response>"""


def _nested_status():
    return samlp.Status(
        status_code=samlp.StatusCode(
            value=samlp.STATUS_RESPONDER,
            status_code=samlp.StatusCode(
                value=samlp.STATUS_NO_AUTHN_CONTEXT,
                status_code=samlp.StatusCode(value="https://idp.example.org/status/custom"),
            ),
        ),
        status_message=samlp.StatusMessage(text="arbitrary issuer text"),
    )


def test_status_code_chain_walks_nested_codes():
    chain = status_code_chain(_nested_status())
    assert chain == [samlp.STATUS_RESPONDER, samlp.STATUS_NO_AUTHN_CONTEXT, "https://idp.example.org/status/custom"]


def test_status_code_chain_handles_missing_status():
    assert status_code_chain(None) == []
    assert status_code_chain(samlp.Status()) == []


def test_public_reason_uses_most_specific_known_code():
    chain = status_code_chain(_nested_status())
    assert public_reason_for_status(chain) == "unsupported_authn_context"


def test_public_reason_for_nopassive_and_unknown_fallback():
    assert public_reason_for_status([samlp.STATUS_RESPONDER, samlp.STATUS_NO_PASSIVE]) == "passive_login_not_possible"
    assert public_reason_for_status(["https://idp.example.org/status/cancel"]) == GENERIC_STATUS_REASON


def test_for_status_keeps_raw_message_out_of_public_reason():
    response = samlp.Response(
        id="id-response-1",
        in_response_to="id-request-9",
        issuer=saml.Issuer(text="https://idp.example.org/"),
        status=_nested_status(),
    )
    failure = SAMLFailure.for_status(response.status, response, trusted=True)

    assert failure.category is FailureCategory.STATUS
    assert failure.trusted is True
    assert failure.is_business_failure is True
    assert failure.public_reason == "unsupported_authn_context"
    assert failure.status_codes == [
        samlp.STATUS_RESPONDER,
        samlp.STATUS_NO_AUTHN_CONTEXT,
        "https://idp.example.org/status/custom",
    ]
    assert failure.in_response_to == "id-request-9"
    assert failure.response_id == "id-response-1"
    assert failure.issuer == "https://idp.example.org/"
    # Free text is retained for authenticated diagnostics only and never
    # leaks into the public reason.
    assert failure.raw_status_message == "arbitrary issuer text"
    assert failure.public_reason != failure.raw_status_message


def test_untrusted_status_is_never_a_business_failure():
    response = samlp.Response(status=_nested_status())
    failure = SAMLFailure.for_status(response.status, response, trusted=False)
    assert failure.category is FailureCategory.STATUS
    assert failure.trusted is False
    assert failure.is_business_failure is False


def test_for_malformed_is_untrusted_and_generic():
    failure = SAMLFailure.for_malformed(b"<not-saml/>", detail="boom")
    assert failure.category is FailureCategory.MALFORMED
    assert failure.public_reason == MALFORMED_REASON
    assert failure.trusted is False
    assert failure.is_business_failure is False
    assert failure.detail == "boom"
    assert failure.status_codes == []


def test_for_untrusted_extracts_status_but_keeps_untrusted_flag():
    failure = SAMLFailure.for_untrusted(UNSCOPED_RESPONSE, detail="Signature missing for response")
    assert failure.category is FailureCategory.SIGNATURE
    assert failure.public_reason == UNTRUSTED_REASON
    assert failure.trusted is False
    assert failure.is_business_failure is False
    # The self-asserted status is captured for diagnostics only.
    assert failure.status_codes == [samlp.STATUS_RESPONDER, samlp.STATUS_NO_AUTHN_CONTEXT]
    assert failure.raw_status_message == "reflected <script> text"
    assert failure.in_response_to == "id-request-9"
    assert failure.response_id == "id-response-1"
    assert failure.issuer == "https://idp.example.org/"


def test_for_untrusted_tolerates_garbage():
    failure = SAMLFailure.for_untrusted(b"<<<not xml", detail="bad")
    assert failure.category is FailureCategory.SIGNATURE
    assert failure.trusted is False
    assert failure.status_codes == []


def test_status_from_xml_parses_without_namespace_prefixes():
    status = status_from_xml(UNSCOPED_RESPONSE)
    assert status_code_chain(status) == [samlp.STATUS_RESPONDER, samlp.STATUS_NO_AUTHN_CONTEXT]
    assert status.status_message.text == "reflected <script> text"
    assert status_from_xml(b"<garbage") is None


def test_correlation_from_xml_is_namespace_agnostic():
    correlation = correlation_from_xml(UNSCOPED_RESPONSE)
    assert correlation == {
        "in_response_to": "id-request-9",
        "response_id": "id-response-1",
        "issuer": "https://idp.example.org/",
    }
    assert correlation_from_xml(b"<garbage") == {"in_response_to": None, "response_id": None, "issuer": None}


def test_attach_and_recover_failure():
    failure = SAMLFailure.for_malformed(detail="bad xml")
    error = attach_failure(ValueError("bad xml"), failure)
    assert failure_from_exception(error) is failure
    assert failure_from_exception(RuntimeError("no failure")) is None
