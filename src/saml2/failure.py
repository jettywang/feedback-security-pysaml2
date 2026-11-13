"""Structured representation of SAML response failures.

The legacy response processing in :mod:`saml2.response` only raises
exceptions, which forces every caller to map exception classes back to a
failure reason. This module adds a structured failure result,
:class:`SAMLFailure`, that keeps:

* the full, possibly nested, ``StatusCode`` chain,
* request correlation information (``InResponseTo``, response ``ID`` and
  issuer),
* a public, fixed-vocabulary reason that is safe to show to end users or
* write to logs, and
* whether the result is based on a response whose signature was verified.

A response that could not be authenticated (bad or missing signature,
malformed XML) is never reported as a business-level status failure: its
self-asserted status cannot be trusted and therefore must not be used to
select a login flow. The raw ``StatusMessage`` is never part of the
public reason; callers that need the issuer supplied text can read it
from :attr:`SAMLFailure.raw_status_message`, which is intended for
authenticated, server-side diagnostics only.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional, Sequence
from xml.etree import ElementTree

from saml2 import samlp


class FailureCategory(str, Enum):
    """High level categorisation of a response failure.

    * ``MALFORMED`` - the message could not be parsed or schema validated.
    * ``SIGNATURE`` - the message was parseable but could not be
      authenticated (missing, invalid or untrusted signature).
    * ``STATUS`` - an authenticated response carrying a non-success
      SAML status, for example ``NoAuthnContext`` or ``NoPassive``.
    """

    MALFORMED = "malformed"
    SIGNATURE = "signature"
    STATUS = "status"


# Safe, fixed vocabulary reasons. Only these strings are ever exposed
# through ``SAMLFailure.public_reason``; issuer supplied free text is
# deliberately excluded so it can not be reflected into pages or logs.
_PUBLIC_REASONS = {
    samlp.STATUS_VERSION_MISMATCH: "unsupported_saml_version",
    samlp.STATUS_AUTHN_FAILED: "authentication_failed",
    samlp.STATUS_INVALID_ATTR_NAME_OR_VALUE: "invalid_attribute",
    samlp.STATUS_INVALID_NAMEID_POLICY: "invalid_nameid_policy",
    samlp.STATUS_NO_AUTHN_CONTEXT: "unsupported_authn_context",
    samlp.STATUS_NO_AVAILABLE_IDP: "no_available_idp",
    samlp.STATUS_NO_PASSIVE: "passive_login_not_possible",
    samlp.STATUS_NO_SUPPORTED_IDP: "no_supported_idp",
    samlp.STATUS_PARTIAL_LOGOUT: "partial_logout",
    samlp.STATUS_PROXY_COUNT_EXCEEDED: "proxy_count_exceeded",
    samlp.STATUS_REQUEST_DENIED: "request_denied",
    samlp.STATUS_REQUEST_UNSUPPORTED: "unsupported_request",
    samlp.STATUS_REQUEST_VERSION_DEPRECATED: "deprecated_saml_version",
    samlp.STATUS_REQUEST_VERSION_TOO_HIGH: "unsupported_saml_version",
    samlp.STATUS_REQUEST_VERSION_TOO_LOW: "unsupported_saml_version",
    samlp.STATUS_RESOURCE_NOT_RECOGNIZED: "resource_not_recognized",
    samlp.STATUS_TOO_MANY_RESPONSES: "too_many_responses",
    samlp.STATUS_UNKNOWN_ATTR_PROFILE: "unknown_attribute_profile",
    samlp.STATUS_UNKNOWN_PRINCIPAL: "unknown_principal",
    samlp.STATUS_UNSUPPORTED_BINDING: "unsupported_binding",
    samlp.STATUS_RESPONDER: "responder_error",
}

GENERIC_STATUS_REASON = "request_failed"
MALFORMED_REASON = "malformed_response"
UNTRUSTED_REASON = "untrusted_response"


def status_code_chain(status: Any) -> List[str]:
    """Return the full ``StatusCode`` chain, top level first.

    A SAML status may nest secondary status codes arbitrarily deep. The
    most specific code is the last element of the returned list.
    """
    chain: List[str] = []
    status_code = getattr(status, "status_code", None)
    while status_code is not None:
        value = getattr(status_code, "value", None)
        if value:
            chain.append(value)
        status_code = getattr(status_code, "status_code", None)
    return chain


def public_reason_for_status(chain: Sequence[str]) -> str:
    """Map a status code chain to a fixed public reason.

    The most specific (deepest) known status code wins, so a
    ``Responder / NoAuthnContext`` response reports
    ``unsupported_authn_context`` rather than the generic responder
    reason. Unknown and custom status codes fall back to
    :data:`GENERIC_STATUS_REASON`.
    """
    for value in reversed(list(chain)):
        reason = _PUBLIC_REASONS.get(value)
        if reason:
            return reason
    return GENERIC_STATUS_REASON


def _localname(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def status_from_xml(xml_data: Any) -> Optional[Any]:
    """Best effort parse of the ``Status`` element of a SAML response.

    Used when the structured response object is unavailable, typically
    because signature verification or full schema parsing failed. The
    result is only used for diagnostics on untrusted messages, so any
    parse error is swallowed and ``None`` is returned.
    """
    if isinstance(xml_data, str):
        xml_data = xml_data.encode("utf-8")
    try:
        root = ElementTree.fromstring(xml_data)
    except ElementTree.ParseError:
        return None

    for node in root.iter():
        if _localname(node.tag) == "Status":
            try:
                return samlp.status_from_string(ElementTree.tostring(node))
            except Exception:
                return None
    return None


def correlation_from_response(response: Any) -> dict:
    """Extract request correlation fields from a parsed SAML response."""
    return {
        "in_response_to": getattr(response, "in_response_to", None),
        "response_id": getattr(response, "id", None),
        "issuer": (response.issuer.text if getattr(response, "issuer", None) is not None else None),
    }


def correlation_from_xml(xml_data: Any) -> dict:
    """Best effort correlation extraction from raw response XML.

    Namespace agnostic ElementTree access is used because the message is,
    by definition, untrusted at this point. Missing or malformed fields
    simply come back as ``None``.
    """
    correlation = {"in_response_to": None, "response_id": None, "issuer": None}
    if isinstance(xml_data, bytes):
        try:
            xml_data = xml_data.decode("utf-8")
        except UnicodeDecodeError:
            return correlation
    try:
        root = ElementTree.fromstring(xml_data)
    except ElementTree.ParseError:
        return correlation

    correlation["in_response_to"] = root.attrib.get("InResponseTo")
    correlation["response_id"] = root.attrib.get("ID")
    for node in root:
        if _localname(node.tag) == "Issuer":
            correlation["issuer"] = (node.text or "").strip() or None
            break
    return correlation


@dataclass
class SAMLFailure:
    """Structured description of a failed SAML response.

    Instances are attached to the legacy exceptions (see
    :func:`attach_failure`) and are also returned by the response level
    helper :meth:`saml2.response.StatusResponse.build_failure`. The
    dataclass is immutable so callers can safely share failure results
    between the protocol layer and the business layer.
    """

    category: FailureCategory
    public_reason: str
    trusted: bool
    status_codes: List[str] = field(default_factory=list)
    in_response_to: Optional[str] = None
    response_id: Optional[str] = None
    issuer: Optional[str] = None
    raw_status_message: Optional[str] = None
    detail: Optional[str] = None

    @property
    def is_business_failure(self) -> bool:
        """Whether the application may treat this as an IdP reported failure.

        Only an authenticated status failure qualifies. Malformed or
        unauthenticated responses stay protocol level rejections and must
        never drive a login flow change.
        """
        return self.trusted and self.category is FailureCategory.STATUS

    @classmethod
    def for_status(cls, status: Any, response: Any, trusted: bool) -> "SAMLFailure":
        chain = status_code_chain(status)
        status_message = getattr(status, "status_message", None)
        raw_message = getattr(status_message, "text", None) if status_message is not None else None
        correlation = correlation_from_response(response)
        return cls(
            category=FailureCategory.STATUS,
            public_reason=public_reason_for_status(chain),
            trusted=trusted,
            status_codes=chain,
            raw_status_message=raw_message,
            **correlation,
        )

    @classmethod
    def for_malformed(cls, xml_data: Any = None, detail: Optional[str] = None) -> "SAMLFailure":
        correlation = correlation_from_xml(xml_data) if xml_data else {}
        return cls(
            category=FailureCategory.MALFORMED,
            public_reason=MALFORMED_REASON,
            trusted=False,
            detail=detail,
            **correlation,
        )

    @classmethod
    def for_untrusted(cls, xml_data: Any = None, detail: Optional[str] = None) -> "SAMLFailure":
        correlation = {}
        chain: List[str] = []
        raw_message = None
        if xml_data:
            correlation = correlation_from_xml(xml_data)
            status = status_from_xml(xml_data)
            if status is not None:
                chain = status_code_chain(status)
                status_message = getattr(status, "status_message", None)
                if status_message is not None:
                    raw_message = getattr(status_message, "text", None)
        return cls(
            category=FailureCategory.SIGNATURE,
            public_reason=UNTRUSTED_REASON,
            trusted=False,
            status_codes=chain,
            raw_status_message=raw_message,
            detail=detail,
            **correlation,
        )


def attach_failure(exception: BaseException, failure: SAMLFailure) -> BaseException:
    """Attach a structured failure to a legacy exception and return it.

    Existing call sites keep raising the same exception classes; new
    callers can read ``exception.failure`` instead of re-interpreting the
    class hierarchy.
    """
    exception.failure = failure  # type: ignore[attr-defined]
    return exception


def failure_from_exception(exception: BaseException) -> Optional[SAMLFailure]:
    """Return the structured failure attached to an exception, if any."""
    return getattr(exception, "failure", None)
