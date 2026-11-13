"""Unit tests for the proxy decision rules (pure object logic, no xmlsec).

Run from the repo root: .venv/bin/python -m pytest proxy_design/test_proxy_policy.py
"""
import calendar
import time

import pytest

from saml2 import saml
from saml2.time_util import instant

import proxy_policy

PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
MFA = "https://refeds.org/profile/mfa"
UPSTREAM = "https://idp.example.com/entity"
PROXY = "https://proxy.example.com/entity"
SP = "https://sp.example.com/entity"
OTHER = "https://other.example.com/entity"


def _assertion(*, count=None, audiences=None, authn_class=PPT, expiry_shift=900,
               session_shift=1800, authenticating_authorities=None):
    now = calendar.timegm(time.gmtime())
    context = saml.AuthnContext(
        authn_context_class_ref=saml.AuthnContextClassRef(text=authn_class),
        authenticating_authority=[
            saml.AuthenticatingAuthority(text=a) for a in (authenticating_authorities or [UPSTREAM])
        ],
    )
    statement = saml.AuthnStatement(
        authn_instant=instant(time_stamp=now - 300),
        session_not_on_or_after=instant(time_stamp=now + session_shift),
        authn_context=context,
    )
    conditions = saml.Conditions(
        not_before=instant(time_stamp=now - 60),
        not_on_or_after=instant(time_stamp=now + expiry_shift),
        audience_restriction=[saml.AudienceRestriction(audience=[saml.Audience(text=PROXY)])],
    )
    if count is not None or audiences:
        conditions.proxy_restriction = [
            saml.ProxyRestriction(
                count=None if count is None else str(count),
                audience=[saml.Audience(text=a) for a in (audiences or [])],
            )
        ]
    return saml.Assertion(
        id="id-test", version="2.0", issue_instant=instant(),
        issuer=saml.Issuer(text=UPSTREAM), conditions=conditions,
        authn_statement=[statement],
    )


def test_allow_when_count_audience_and_strength_permit():
    decision = proxy_policy.evaluate_proxy(_assertion(count=2, audiences=[SP]), SP, PPT)
    assert decision.allowed
    assert decision.remaining_count == 2


def test_count_zero_denies_even_if_audience_matches():
    decision = proxy_policy.evaluate_proxy(_assertion(count=0, audiences=[SP]), SP, PPT)
    assert decision.decision is proxy_policy.Decision.DENY_COUNT_EXHAUSTED


def test_audience_out_of_scope_denies():
    decision = proxy_policy.evaluate_proxy(_assertion(count=1, audiences=[SP]), OTHER, PPT)
    assert decision.decision is proxy_policy.Decision.DENY_AUDIENCE_OUT_OF_SCOPE


def test_missing_count_means_unlimited_but_audience_still_applies():
    decision = proxy_policy.evaluate_proxy(_assertion(audiences=[SP]), SP, PPT)
    assert decision.allowed and decision.remaining_count is None
    denied = proxy_policy.evaluate_proxy(_assertion(audiences=[SP]), OTHER, PPT)
    assert denied.decision is proxy_policy.Decision.DENY_AUDIENCE_OUT_OF_SCOPE


def test_strength_upgrade_is_incomparable_and_denied():
    decision = proxy_policy.evaluate_proxy(_assertion(count=1, audiences=[SP], authn_class=PPT), SP, MFA)
    assert decision.decision is proxy_policy.Decision.DENY_STRENGTH_INCOMPARABLE


def test_unknown_class_ref_is_incomparable_not_guessed():
    assertion = _assertion(count=1, audiences=[SP], authn_class="urn:unknown:ac:classes:Weird")
    decision = proxy_policy.evaluate_proxy(assertion, SP, PPT)
    assert decision.decision is proxy_policy.Decision.DENY_STRENGTH_INCOMPARABLE


def test_expired_assertion_denied():
    assertion = _assertion(count=1, audiences=[SP])
    future = calendar.timegm(time.gmtime()) + 10000
    decision = proxy_policy.evaluate_proxy(assertion, SP, PPT, now_epoch=future)
    assert decision.decision is proxy_policy.Decision.DENY_EXPIRED


def test_reissue_decrements_count_preserves_instant_and_chains_authorities():
    upstream = _assertion(count=1, audiences=[SP])
    original_instant = upstream.authn_statement[0].authn_instant
    decision = proxy_policy.evaluate_proxy(upstream, SP, PPT)
    now = calendar.timegm(time.gmtime())
    reissued = proxy_policy.apply_proxy_constraints(
        upstream, decision, PROXY, SP,
        downstream_conditions_nooa=decision.downstream_expiry,
        downstream_session_nooa=decision.downstream_expiry,
    )
    assert reissued.issuer.text == PROXY
    assert reissued.authn_statement[0].authn_instant == original_instant
    assert reissued.conditions.proxy_restriction[0].count == "0"
    authorities = [a.text for a in reissued.authn_statement[0].authn_context.authenticating_authority]
    assert authorities == [UPSTREAM, PROXY]
    assert SP in [a.text for ar in reissued.conditions.audience_restriction for a in ar.audience]


def test_downstream_bounds_cannot_exceed_upstream_ceiling():
    upstream = _assertion(count=1, audiences=[SP])
    decision = proxy_policy.evaluate_proxy(upstream, SP, PPT)
    now = calendar.timegm(time.gmtime())
    conditions_nooa, session_nooa = proxy_policy.downstream_time_bounds(
        decision, now + 99999, now + 99999
    )
    assert conditions_nooa <= decision.downstream_expiry
    assert session_nooa <= decision.downstream_expiry
    with pytest.raises(proxy_policy.ProxyRuleError):
        proxy_policy.apply_proxy_constraints(
            upstream, decision, PROXY, SP, now + 99999, now + 99999
        )


def test_reissue_refused_after_deny():
    upstream = _assertion(count=0, audiences=[SP])
    decision = proxy_policy.evaluate_proxy(upstream, SP, PPT)
    now = calendar.timegm(time.gmtime())
    with pytest.raises(proxy_policy.ProxyRuleError):
        proxy_policy.apply_proxy_constraints(
            upstream, decision, PROXY, SP, now + 600, now + 600
        )


def test_unlimited_count_emits_no_new_proxy_restriction():
    upstream = _assertion(audiences=[SP])  # no Count
    decision = proxy_policy.evaluate_proxy(upstream, SP, PPT)
    assert proxy_policy.next_proxy_restriction(decision) is None
