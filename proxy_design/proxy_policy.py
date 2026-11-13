"""Proxy decision rules for a PySAML2-based IdP proxy.

This module is policy-only: it operates on parsed saml2 objects
(``saml.Assertion`` / ``saml.AuthnStatement`` / ``saml.Conditions``) and never
touches signatures.  Signature verification is a precondition that happens in
``saml2.response.AuthnResponse`` before any function here is called; a valid
upstream signature proves *who asserted the data*, it does not authorize the
proxy to upgrade or rewrite the authentication context.

SAML 2.0 core, section 3.4.1.5 (ProxyRestriction):
  * Count absent  -> no limit on proxying
  * Count=0       -> the asserting party explicitly forbids further proxying
  * Count=n       -> at most n further proxying parties
  * nested <Audience> -> the next party (or proxied parties) must be among them
"""
from __future__ import annotations

import calendar
from dataclasses import dataclass
from enum import Enum

from saml2 import saml
from saml2.time_util import str_to_time


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY_COUNT_EXHAUSTED = "DENY_COUNT_EXHAUSTED"
    DENY_AUDIENCE_OUT_OF_SCOPE = "DENY_AUDIENCE_OUT_OF_SCOPE"
    DENY_EXPIRED = "DENY_EXPIRED"
    DENY_STRENGTH_INCOMPARABLE = "DENY_STRENGTH_INCOMPARABLE"


class ProxyRuleError(Exception):
    """Raised when caller code asks the proxy to do something the policy forbids."""


@dataclass(frozen=True)
class ProxyDecision:
    decision: Decision
    reason: str
    remaining_count: int | None
    downstream_expiry: int  # epoch seconds, hard ceiling for the downstream assertion
    strength_comparable: bool

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


# Ordered AuthnContextClassRef levels. Anything outside this table is treated as
# incomparable rather than guessed at: the proxy must not invent an ordering.
DEFAULT_STRENGTH_ORDER = {
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Password": 10,
    "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport": 20,
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient": 30,
    "urn:oasis:names:tc:SAML:2.0:ac:classes:X509": 30,
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract": 40,
    "https://refeds.org/profile/mfa": 50,
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken": 50,
}


def _epoch(value: str | None) -> int | None:
    if not value:
        return None
    return calendar.timegm(str_to_time(value))


def _assertion_expiry(assertion: saml.Assertion) -> int | None:
    """All upstream time bounds that constrain downstream re-use."""
    bounds = []
    conditions = assertion.conditions
    if conditions is not None and conditions.not_on_or_after:
        bounds.append(_epoch(conditions.not_on_or_after))
    for statement in getattr(assertion, "authn_statement", []) or []:
        if statement.session_not_on_or_after:
            bounds.append(_epoch(statement.session_not_on_or_after))
    bounds = [b for b in bounds if b]
    return min(bounds) if bounds else None


def _proxy_restriction(assertion: saml.Assertion) -> saml.ProxyRestriction | None:
    conditions = assertion.conditions
    if conditions is None or not conditions.proxy_restriction:
        return None
    # saml.ConditionsType_.verify() already enforces cardinality <= 1.
    return conditions.proxy_restriction[0]


def remaining_proxy_count(assertion: saml.Assertion) -> int | None:
    """Remaining proxy hops. None means the upstream set no Count limit."""
    restriction = _proxy_restriction(assertion)
    if restriction is None or restriction.count is None:
        return None
    # saml2 stores nonNegativeInteger attributes as strings.
    return int(restriction.count)


def upstream_audiences(assertion: saml.Assertion) -> list[str]:
    restriction = _proxy_restriction(assertion)
    if restriction is None:
        return []
    return [aud.text.strip() for aud in restriction.audience if aud.text]


def _audience_in_scope(assertion: saml.Assertion, downstream_sp_entity_id: str) -> bool:
    allowed = upstream_audiences(assertion)
    # No <Audience> inside ProxyRestriction: Count is the only limit.
    return not allowed or downstream_sp_entity_id in allowed


def _authn_class(assertion: saml.Assertion) -> str | None:
    for statement in getattr(assertion, "authn_statement", []) or []:
        context = statement.authn_context
        if context is None:
            continue
        class_ref = context.authn_context_class_ref
        if class_ref is not None and class_ref.text:
            return class_ref.text.strip()
    return None


def strength_comparable(upstream_class: str | None, requested_class: str | None,
                        order: dict[str, int] | None = None) -> bool:
    """True only when the proxy can prove the upstream level meets the request.

    A missing or unknown class ref, or a requested ref with no shared ordering
    table, is incomparable -> deny, never silently upgraded.
    """
    order = order or DEFAULT_STRENGTH_ORDER
    if not upstream_class or not requested_class:
        return False
    if upstream_class not in order or requested_class not in order:
        return False
    return order[upstream_class] >= order[requested_class]


def evaluate_proxy(assertion: saml.Assertion,
                   downstream_sp_entity_id: str,
                   requested_authn_class: str | None = None,
                   now_epoch: int | None = None,
                   strength_order: dict[str, int] | None = None) -> ProxyDecision:
    """Single decision point the proxy service must call before issuing anything.

    Inputs are the *signature-verified* upstream assertion plus the downstream
    request context.  The function is pure: no XML mutation, no signing.
    """
    import time
    now = now_epoch if now_epoch is not None else calendar.timegm(time.gmtime())

    remaining = remaining_proxy_count(assertion)
    if remaining is not None and remaining <= 0:
        return ProxyDecision(
            Decision.DENY_COUNT_EXHAUSTED,
            f"upstream ProxyRestriction Count={remaining} forbids further proxying",
            remaining, 0, False,
        )

    if not _audience_in_scope(assertion, downstream_sp_entity_id):
        return ProxyDecision(
            Decision.DENY_AUDIENCE_OUT_OF_SCOPE,
            f"downstream SP {downstream_sp_entity_id!r} not in ProxyRestriction Audience "
            f"{upstream_audiences(assertion)}",
            remaining, 0, False,
        )

    expiry = _assertion_expiry(assertion)
    if expiry is not None and expiry <= now:
        return ProxyDecision(
            Decision.DENY_EXPIRED,
            "upstream Conditions/SessionNotOnOrAfter already expired at the proxy",
            remaining, expiry, False,
        )

    upstream_class = _authn_class(assertion)
    comparable = strength_comparable(upstream_class, requested_authn_class, strength_order)
    if requested_authn_class and not comparable:
        return ProxyDecision(
            Decision.DENY_STRENGTH_INCOMPARABLE,
            f"upstream class {upstream_class!r} cannot be shown to satisfy "
            f"requested class {requested_authn_class!r}; upgrading is not permitted",
            remaining, expiry or 0, False,
        )

    return ProxyDecision(
        Decision.ALLOW,
        "proxy permitted; downstream bounds must be clamped to upstream bounds",
        remaining, expiry or 0, comparable if requested_authn_class else True,
    )


# ---------------------------------------------------------------------------
# Re-issuance helpers: every setter here is constrained by the decision above.
# ---------------------------------------------------------------------------

def next_proxy_restriction(decision: ProxyDecision) -> saml.ProxyRestriction | None:
    """Decrement Count for the assertion issued to the downstream SP."""
    if decision.remaining_count is None:
        return None  # upstream imposed no count limit -> do not invent one
    next_count = decision.remaining_count - 1
    # The saml2 model serializes nonNegativeInteger as a string.
    return saml.ProxyRestriction(count=str(next_count))


def downstream_time_bounds(decision: ProxyDecision,
                           requested_conditions_not_on_or_after: int,
                           requested_session_not_on_or_after: int | None = None) -> tuple[int, int]:
    """Clamp every downstream expiry to the upstream hard ceiling.

    The proxy can only *shorten* validity; extending it would manufacture
    lifetime the upstream never granted.
    """
    ceiling = decision.downstream_expiry
    if ceiling:
        conditions_nooa = min(requested_conditions_not_on_or_after, ceiling)
        session_nooa = min(requested_session_not_on_or_after, ceiling) \
            if requested_session_not_on_or_after else ceiling
    else:
        conditions_nooa = requested_conditions_not_on_or_after
        session_nooa = requested_session_not_on_or_after or conditions_nooa
    return conditions_nooa, session_nooa


def chain_authenticating_authorities(assertion: saml.Assertion,
                                     proxy_entity_id: str) -> list[saml.AuthenticatingAuthority]:
    """Build the ordered AuthenticatingAuthority chain for a re-issued assertion.

    The upstream chain is preserved verbatim and the proxy appends itself last;
    the original IdP stays the first entry.  The AuthnInstant/AuthnContextClassRef
    of the *upstream* AuthnStatement must be reused unchanged (see design doc),
    so the downstream cannot mistake the proxy for the original authenticator.
    """
    chained: list[saml.AuthenticatingAuthority] = []
    seen: set[str] = set()
    for statement in getattr(assertion, "authn_statement", []) or []:
        context = statement.authn_context
        if context is None:
            continue
        for authority in context.authenticating_authority or []:
            if authority.text and authority.text not in seen:
                seen.add(authority.text)
                chained.append(saml.AuthenticatingAuthority(text=authority.text))
    if proxy_entity_id not in seen:
        chained.append(saml.AuthenticatingAuthority(text=proxy_entity_id))
    return chained


def apply_proxy_constraints(assertion: saml.Assertion,
                            decision: ProxyDecision,
                            proxy_entity_id: str,
                            downstream_sp_entity_id: str,
                            downstream_conditions_nooa: int,
                            downstream_session_nooa: int) -> saml.Assertion:
    """Mutate a *copy* of the upstream assertion for re-issuance.

    Raises ProxyRuleError if the caller skipped evaluate_proxy() or tries to
    extend validity.  Mirrors the gaps in saml2.response.AuthnResponse.condition_ok
    (which never reads conditions.proxy_restriction) by enforcing the rules here.
    """
    if not decision.allowed:
        raise ProxyRuleError(f"cannot re-issue under decision {decision.decision}: {decision.reason}")

    import copy
    from saml2.time_util import instant

    new_assertion = copy.deepcopy(assertion)

    # A re-issued assertion is signed afresh by the proxy; keeping the upstream
    # enveloped Signature would leave an old KeyInfo in place and xmlsec1 reuses
    # it instead of embedding the proxy certificate.
    new_assertion.signature = None

    # The re-issued assertion is a new claim made by the proxy, so the Issuer
    # becomes the proxy. The original IdP remains attributable through the
    # chained AuthenticatingAuthority / preserved AuthnInstant below.
    if new_assertion.issuer is not None:
        new_assertion.issuer.text = proxy_entity_id
    else:
        new_assertion.issuer = saml.Issuer(text=proxy_entity_id)

    conditions = new_assertion.conditions or saml.Conditions()
    new_assertion.conditions = conditions

    upstream_ceiling = decision.downstream_expiry
    if upstream_ceiling and downstream_conditions_nooa > upstream_ceiling:
        raise ProxyRuleError("downstream Conditions NotOnOrAfter exceeds upstream ceiling")

    if conditions.not_on_or_after:
        conditions.not_on_or_after = instant(time_stamp=downstream_conditions_nooa)

    restriction = next_proxy_restriction(decision)
    if restriction is not None:
        conditions.proxy_restriction = [restriction]

    # Re-target AudienceRestriction at the downstream SP while preserving any
    # other AudienceRestriction entries the upstream asserted.
    conditions.audience_restriction = list(conditions.audience_restriction or [])
    conditions.audience_restriction.append(
        saml.AudienceRestriction(audience=[saml.Audience(text=downstream_sp_entity_id)])
    )

    for statement in getattr(new_assertion, "authn_statement", []) or []:
        # AuthnInstant is deliberately left untouched: it marks when the user
        # actually authenticated at the upstream IdP, not when the proxy ran.
        if statement.session_not_on_or_after and upstream_ceiling:
            upstream_session = _epoch(statement.session_not_on_or_after)
            if downstream_session_nooa > (upstream_session or upstream_ceiling):
                raise ProxyRuleError("downstream SessionNotOnOrAfter exceeds upstream ceiling")
        statement.session_not_on_or_after = instant(time_stamp=downstream_session_nooa)
        if statement.authn_context is not None:
            statement.authn_context.authenticating_authority = chain_authenticating_authorities(
                assertion, proxy_entity_id
            )

    return new_assertion
