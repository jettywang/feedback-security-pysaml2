#!/usr/bin/env python3
"""In-memory experiment: PySAML2 IdP proxy, direct-forward vs constrained re-issue.

Everything runs inside one process against the real saml2 classes:
  * an upstream IdP (saml2.server.Server) mints signed assertions carrying
    AuthnInstant / AuthenticatingAuthority / SessionNotOnOrAfter /
    AudienceRestriction / ProxyRestriction;
  * the proxy first verifies the upstream Response with saml2.response.AuthnResponse
    (real xmlsec1 signature check), then applies proxy_policy.evaluate_proxy();
  * two issuance strategies are compared:
      - direct forward : original signed XML is passed on untouched;
      - re-issue        : proxy signs a new assertion whose context is *clamped*
                          to the upstream bounds (Count-1, same AuthnInstant,
                          shortened lifetime, chained AuthenticatingAuthority,
                          unchanged/non-upgraded AuthnContextClassRef);
  * a downstream SP verifies whatever it received with saml2 again.

The four mandated decision-table scenarios are exercised at the end.
Run: .venv/bin/python proxy_design/proxy_experiment.py
"""
from __future__ import annotations

import calendar
import copy
import os
import time
from dataclasses import dataclass

from saml2 import BINDING_HTTP_POST
from saml2 import class_name
from saml2 import saml
from saml2 import samlp
from saml2 import time_util
from saml2.config import IdPConfig
from saml2.server import Server
from saml2.sigver import get_xmlsec_binary

import proxy_policy

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(HERE)
TEST_KEY = os.path.join(REPO_ROOT, "tests", "test.key")
TEST_CERT = os.path.join(REPO_ROOT, "tests", "test.pem")
PROXY_KEY = os.path.join(os.environ.get("TMPDIR", "/tmp"), "proxy.key")
PROXY_CERT = os.path.join(os.environ.get("TMPDIR", "/tmp"), "proxy.crt")

UPSTREAM_IDP = "https://idp.example.com/entity"
PROXY_ENTITY = "https://proxy.example.com/entity"
DOWNSTREAM_SP = "https://sp.example.com/entity"
OTHER_SP = "https://other-sp.example.com/entity"

PPT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
MFA = "https://refeds.org/profile/mfa"


def _idp_config(entity_id, key_file, cert_file):
    conf = IdPConfig()
    conf.load(
        {
            "entityid": entity_id,
            "service": {
                "idp": {
                    "endpoints": {
                        "single_sign_on_service": [
                            (f"{entity_id}/sso", BINDING_HTTP_POST),
                        ],
                    },
                    "policy": {
                        "default": {"lifetime": {"minutes": 15}, "name_form": saml.NAME_FORMAT_URI},
                    },
                }
            },
            "key_file": key_file,
            "cert_file": cert_file,
            "xmlsec_binary": get_xmlsec_binary(),
            "debug": 0,
        }
    )
    return conf


def _security_context(key_file, cert_file):
    """Standalone SecurityContext: embedded-key trust, no metadata needed."""
    from saml2.sigver import CryptoBackendXmlSec1
    from saml2.sigver import SecurityContext
    crypto = CryptoBackendXmlSec1(get_xmlsec_binary())
    return SecurityContext(crypto, key_file=key_file, cert_file=cert_file,
                           only_use_keys_in_metadata=False)


def _verify_signed_assertion(assertion_xml: str, verifier) -> saml.Assertion:
    """Real xmlsec1 signature check on the exact bytes that were transported."""
    assertion = saml.assertion_from_string(assertion_xml)
    verifier.check_signature(assertion, class_name(saml.Assertion()), origdoc=assertion_xml)
    return assertion


def _validate_conditions(assertion: saml.Assertion, receiver_entity_id: str, timeslack: int = 60):
    """Reuse saml2's own condition primitives (time window + AudienceRestriction).

    This is the same logic AuthnResponse.condition_ok()/for_me() run; it is
    invoked directly because the experiment exchanges bare signed Assertions.
    """
    from saml2.response import for_me
    from saml2.validate import validate_before
    from saml2.validate import validate_on_or_after
    conditions = assertion.conditions
    if conditions.not_on_or_after:
        validate_on_or_after(conditions.not_on_or_after, timeslack)
    if conditions.not_before:
        validate_before(conditions.not_before, timeslack)
    if not for_me(conditions, receiver_entity_id):
        raise AssertionError(f"AudienceRestriction not satisfied for {receiver_entity_id}")
    for statement in assertion.authn_statement:
        if statement.session_not_on_or_after:
            validate_on_or_after(statement.session_not_on_or_after, timeslack)


@dataclass
class UpstreamFixture:
    assertion_xml: str
    assertion: saml.Assertion


class ProxyLab:
    def __init__(self):
        self.upstream = Server(config=_idp_config(UPSTREAM_IDP, TEST_KEY, TEST_CERT))
        self.proxy_idp = Server(config=_idp_config(PROXY_ENTITY, PROXY_KEY, PROXY_CERT))
        # The proxy trusts the upstream cert; the downstream SP trusts the proxy cert.
        self.upstream_verifier = _security_context(TEST_KEY, TEST_CERT)
        self.proxy_verifier = _security_context(PROXY_KEY, PROXY_CERT)

    def close(self):
        self.upstream.close()
        self.proxy_idp.close()

    # -- upstream side ------------------------------------------------------
    def mint_upstream_assertion(self, *, count=None, proxy_audiences=None,
                                authn_class=PPT,
                                session_ttl_seconds=1800,
                                audience=PROXY_ENTITY,
                                authenticating_authorities=None) -> UpstreamFixture:
        """Build an upstream assertion with explicit proxy-relevant fields."""
        name_id = self.upstream.ident.transient_nameid(audience, "req-1")
        now = calendar.timegm(time.gmtime())
        session_nooa = time_util.instant(time_stamp=now + session_ttl_seconds)

        authn = {
            "class_ref": authn_class,
            "authn_instant": now - 300,  # user actually authenticated 5 min ago
            "authn_auth": (authenticating_authorities or [UPSTREAM_IDP])[0],
        }

        resp_xml = self.upstream.create_authn_response(
            {"givenName": ["Alice"], "mail": ["alice@example.com"]},
            "req-1",
            f"{audience}/acs",
            audience,
            name_id=name_id,
            sign_assertion=True,
            authn=authn,
            session_not_on_or_after=session_nooa,
        )

        assertion = samlp.response_from_string(resp_xml).assertion[0]

        # Inject the ProxyRestriction the way an enterprise IdP would express it.
        # The object is mutated while unsigned and then signed once; every party
        # verifies the exact signed bytes, so no canonicalization can drift.
        if count is not None or proxy_audiences:
            restriction = saml.ProxyRestriction(
                count=None if count is None else str(count),
                audience=[saml.Audience(text=a) for a in (proxy_audiences or [])],
            )
            assertion.conditions.proxy_restriction = [restriction]

        assertion_xml = self.upstream.sec.sign_assertion(assertion)
        signed = saml.assertion_from_string(assertion_xml)
        return UpstreamFixture(assertion_xml, signed)

    # -- proxy side: verification must happen before any policy decision -----
    def verify_upstream(self, fixture: UpstreamFixture):
        assertion = _verify_signed_assertion(fixture.assertion_xml, self.upstream_verifier)
        _validate_conditions(assertion, PROXY_ENTITY)
        return assertion

    def verify_downstream(self, assertion_xml: str, receiver_entity_id: str, verifier):
        assertion = _verify_signed_assertion(assertion_xml, verifier)
        _validate_conditions(assertion, receiver_entity_id)
        return assertion

    # -- strategy A: direct forward -----------------------------------------
    def direct_forward(self, fixture: UpstreamFixture):
        """The proxy relays the original signed bytes untouched."""
        return fixture.assertion_xml

    # -- strategy B: constrained re-issue -----------------------------------
    def reissue(self, fixture: UpstreamFixture, decision: proxy_policy.ProxyDecision,
                downstream_sp=DOWNSTREAM_SP, requested_ttl=3600):
        """Re-sign with the proxy key under the clamped policy decision."""
        now = calendar.timegm(time.gmtime())
        wanted_conditions_nooa = now + requested_ttl  # SP would like a long lifetime
        wanted_session_nooa = now + requested_ttl

        conditions_nooa, session_nooa = proxy_policy.downstream_time_bounds(
            decision, wanted_conditions_nooa, wanted_session_nooa
        )
        new_assertion = proxy_policy.apply_proxy_constraints(
            fixture.assertion,
            decision,
            proxy_entity_id=PROXY_ENTITY,
            downstream_sp_entity_id=downstream_sp,
            downstream_conditions_nooa=conditions_nooa,
            downstream_session_nooa=session_nooa,
        )
        # apply_proxy_constraints() drops the upstream enveloped signature;
        # xmlsec1 needs a Signature template, preset with the proxy's own cert.
        from saml2.sigver import pre_signature_part
        new_assertion.signature = pre_signature_part(new_assertion.id, self.proxy_idp.sec.my_cert)
        return self.proxy_idp.sec.sign_assertion(new_assertion)


def _summarize_assertion(assertion_xml: str, label):
    assertion = saml.assertion_from_string(assertion_xml)
    statement = assertion.authn_statement[0]
    context = statement.authn_context
    restriction = assertion.conditions.proxy_restriction[0] if assertion.conditions.proxy_restriction else None
    return {
        "label": label,
        "issuer": assertion.issuer.text,
        "authn_instant": statement.authn_instant,
        "class_ref": context.authn_context_class_ref.text,
        "authenticating_authorities": [a.text for a in context.authenticating_authority],
        "conditions_nooa": assertion.conditions.not_on_or_after,
        "session_nooa": statement.session_not_on_or_after,
        "audiences": [a.text for ar in assertion.conditions.audience_restriction for a in ar.audience],
        "proxy_count": None if restriction is None else restriction.count,
        "proxy_audiences": [a.text for a in restriction.audience] if restriction else [],
    }


def _print_row(row):
    print(f"  [{row['label']}]")
    print(f"    issuer                     : {row['issuer']}")
    print(f"    AuthnInstant               : {row['authn_instant']} (upstream login instant preserved)")
    print(f"    AuthnContextClassRef       : {row['class_ref']}")
    print(f"    AuthenticatingAuthority    : {' -> '.join(row['authenticating_authorities'])}")
    print(f"    Conditions NotOnOrAfter    : {row['conditions_nooa']}")
    print(f"    SessionNotOnOrAfter        : {row['session_nooa']}")
    print(f"    AudienceRestriction        : {row['audiences']}")
    print(f"    ProxyRestriction Count     : {row['proxy_count']}")
    print(f"    ProxyRestriction Audience  : {row['proxy_audiences']}")


def main():
    lab = ProxyLab()
    try:
        print("=" * 78)
        print("SCENARIO 0 - happy path: upstream allows one proxy hop (Count=1)")
        print("=" * 78)
        fixture = lab.mint_upstream_assertion(
            count=1, proxy_audiences=[DOWNSTREAM_SP], session_ttl_seconds=1800
        )
        lab.verify_upstream(fixture)  # real signature + condition check at the proxy
        decision = proxy_policy.evaluate_proxy(fixture.assertion, DOWNSTREAM_SP, requested_authn_class=PPT)
        print(f"  policy decision            : {decision.decision.value} ({decision.reason})")
        assert decision.allowed

        forwarded = lab.direct_forward(fixture)
        reissued = lab.reissue(fixture, decision)

        row_fwd = _summarize_assertion(forwarded, "A direct-forward")
        row_new = _summarize_assertion(reissued, "B re-issued")
        _print_row(row_fwd)
        _print_row(row_new)

        # Downstream SP runs real xmlsec1 signature checks plus saml2's own
        # condition primitives on whatever the proxy handed it.
        new_assertion = lab.verify_downstream(reissued, DOWNSTREAM_SP, lab.proxy_verifier)
        print(f"  downstream verifies reissue : issuer={new_assertion.issuer.text} (proxy signature), "
              f"AudienceRestriction now contains {DOWNSTREAM_SP}")

        # Direct-forward keeps the upstream signature valid, but the assertion
        # remains addressed to the proxy: AudienceRestriction fails at the SP.
        fwd_assertion = _verify_signed_assertion(forwarded, lab.upstream_verifier)
        try:
            _validate_conditions(fwd_assertion, DOWNSTREAM_SP)
        except AssertionError as exc:
            print(f"  direct-forward rejected by SP: {exc} (signature valid, audience is the proxy)")
        else:
            raise AssertionError("direct-forward should fail audience validation at the SP")

        # Non-regression assertions on the invariants.
        upstream_row = _summarize_assertion(fixture.assertion_xml, "upstream original")
        assert row_new["authn_instant"] == upstream_row["authn_instant"], "AuthnInstant must not be renewed"
        assert row_new["class_ref"] == PPT, "Authn strength must not be upgraded"
        assert int(row_new["proxy_count"]) == 0, "Count must be decremented to zero"
        assert UPSTREAM_IDP in row_new["authenticating_authorities"]
        assert PROXY_ENTITY in row_new["authenticating_authorities"]
        assert row_new["authenticating_authorities"][-1] == PROXY_ENTITY
        assert time_util.str_to_time(row_new["conditions_nooa"]) <= time_util.str_to_time(
            upstream_row["conditions_nooa"]
        ), "re-issued validity must be clamped, never extended"

        print()
        print("=" * 78)
        print("DECISION TABLE - evaluate_proxy() over the mandated cases")
        print("=" * 78)
        table = []

        # 1. proxy allowed
        f_allow = lab.mint_upstream_assertion(count=2, proxy_audiences=[DOWNSTREAM_SP])
        d_allow = proxy_policy.evaluate_proxy(f_allow.assertion, DOWNSTREAM_SP, PPT)
        table.append(("proxy allowed (Count=2, audience matches, PPT>=PPT)", d_allow))

        # 2. count exhausted
        f_zero = lab.mint_upstream_assertion(count=0, proxy_audiences=[DOWNSTREAM_SP])
        d_zero = proxy_policy.evaluate_proxy(f_zero.assertion, DOWNSTREAM_SP, PPT)
        table.append(("count exhausted (Count=0)", d_zero))

        # 3. downstream audience out of scope
        f_aud = lab.mint_upstream_assertion(count=1, proxy_audiences=[DOWNSTREAM_SP])
        d_aud = proxy_policy.evaluate_proxy(f_aud.assertion, OTHER_SP, PPT)
        table.append(("downstream audience not in ProxyRestriction Audience", d_aud))

        # 4. strength incomparable: upstream PPT, downstream requires MFA
        f_weak = lab.mint_upstream_assertion(count=1, proxy_audiences=[DOWNSTREAM_SP], authn_class=PPT)
        d_weak = proxy_policy.evaluate_proxy(f_weak.assertion, DOWNSTREAM_SP, MFA)
        table.append(("strength incomparable (PPT upstream, MFA requested)", d_weak))

        # 5. bonus: already expired upstream assertion
        f_exp = lab.mint_upstream_assertion(count=1, proxy_audiences=[DOWNSTREAM_SP])
        past = calendar.timegm(time.gmtime()) - 10
        d_exp = proxy_policy.evaluate_proxy(f_exp.assertion, DOWNSTREAM_SP, PPT, now_epoch=past + 9999)
        table.append(("upstream validity expired before re-issue", d_exp))

        for name, dec in table:
            print(f"  {dec.decision.value:32s} | {name}")
            print(f"  {'':32s} |   reason: {dec.reason}")
            assert dec.allowed == (dec.decision is proxy_policy.Decision.ALLOW)
        assert d_zero.decision is proxy_policy.Decision.DENY_COUNT_EXHAUSTED
        assert d_aud.decision is proxy_policy.Decision.DENY_AUDIENCE_OUT_OF_SCOPE
        assert d_weak.decision is proxy_policy.Decision.DENY_STRENGTH_INCOMPARABLE
        assert d_exp.decision is proxy_policy.Decision.DENY_EXPIRED

        print()
        print("=" * 78)
        print("GUARD RAIL - re-issuing after a DENY must be refused, not papered over")
        print("=" * 78)
        now = calendar.timegm(time.gmtime())
        for label, fixture_denied, dec_denied in (
            ("count exhausted", f_zero, d_zero),
            ("audience out of scope", f_aud, d_aud),
            ("strength incomparable", f_weak, d_weak),
        ):
            try:
                lab.reissue(fixture_denied, dec_denied)
            except proxy_policy.ProxyRuleError as exc:
                print(f"  blocked re-issue ({label}): {exc}")
            else:
                raise AssertionError(f"re-issue should have been blocked: {label}")

        # And the attempted lifetime-extension guard.
        bad_decision = copy.deepcopy(d_allow)
        try:
            proxy_policy.apply_proxy_constraints(
                f_allow.assertion, bad_decision, PROXY_ENTITY, DOWNSTREAM_SP,
                downstream_conditions_nooa=now + 99999,
                downstream_session_nooa=now + 99999,
            )
        except proxy_policy.ProxyRuleError as exc:
            print(f"  blocked lifetime extension: {exc}")
        else:
            raise AssertionError("lifetime extension should have been blocked")

        print()
        print("ALL CHECKS PASSED")
    finally:
        lab.close()


if __name__ == "__main__":
    main()
