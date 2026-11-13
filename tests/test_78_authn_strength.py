"""Tests for the optional authentication context strength partial order."""

from contextlib import closing

import pytest

from saml2.authn_context import AuthnBroker
from saml2.authn_context import authn_context_class_ref
from saml2.authn_context import requested_authn_context
from saml2.authn_strength import AuthnContextStrength
from saml2.authn_strength import AuthnContextStrengthError
from saml2.authn_strength import ComparisonResult
from saml2.authn_strength import context_matches
from saml2.config import SPConfig
from saml2.ident import NameID
from saml2.saml import Assertion
from saml2.saml import AuthnContext
from saml2.saml import AuthnContextClassRef
from saml2.saml import AuthnContextDeclRef
from saml2.saml import AuthnStatement
from saml2.saml import Subject
from saml2.sdb import SessionStorage
from saml2.server import Server


PASSWORD = "urn:example:password"
SMS = "urn:example:sms"
CERT = "urn:example:cert"
MFA = "urn:example:mfa"

DIAMOND = {
    PASSWORD: [SMS, CERT],
    SMS: [MFA],
    CERT: [MFA],
}


def _statement(context, session_index="s1"):
    return AuthnStatement(
        authn_context=AuthnContext(authn_context_class_ref=AuthnContextClassRef(text=context)),
        authn_instant="2026-11-13T00:00:00Z",
        session_index=session_index,
    )


def _store(statement_contexts):
    db = SessionStorage(authn_context_strength=DIAMOND)
    name_id = NameID(text="subject")
    for index, context in enumerate(statement_contexts):
        session_index = f"s{index}"
        assertion = Assertion(
            id=f"assertion-{index}",
            authn_statement=[_statement(context, session_index)],
            subject=Subject(name_id=name_id),
        )
        db.store_assertion(assertion, [])
    return db, name_id


# -- relation ---------------------------------------------------------------


def test_diamond_is_a_partial_order():
    strength = AuthnContextStrength(DIAMOND)

    assert strength.relation(PASSWORD, MFA) == ComparisonResult.WEAKER
    assert strength.relation(MFA, PASSWORD) == ComparisonResult.STRONGER
    assert strength.relation(MFA, MFA) == ComparisonResult.SAME
    assert strength.relation(SMS, CERT) == ComparisonResult.INCOMPARABLE
    assert strength.relation(CERT, SMS) == ComparisonResult.INCOMPARABLE

    # Transitivity across the diamond.
    assert strength.is_stronger(MFA, PASSWORD)


def test_incomparable_methods_do_not_substitute():
    strength = AuthnContextStrength(DIAMOND)

    # Neither second factor may stand in for the other.
    assert not strength.satisfies("exact", SMS, CERT)
    assert not strength.satisfies("minimum", SMS, CERT)
    assert not strength.satisfies("maximum", SMS, CERT)
    assert not strength.satisfies("better", SMS, CERT)

    # Both are individually enough for the password floor.
    assert strength.satisfies("minimum", SMS, PASSWORD)
    assert strength.satisfies("minimum", CERT, PASSWORD)

    # Neither reaches the MFA ceiling on its own.
    assert not strength.satisfies("minimum", SMS, MFA)
    assert not strength.satisfies("minimum", CERT, MFA)
    assert strength.satisfies("minimum", MFA, MFA)


def test_four_comparisons_share_the_same_relation():
    strength = AuthnContextStrength(DIAMOND)

    assert strength.satisfies("exact", SMS, SMS)
    assert not strength.satisfies("exact", MFA, SMS)
    assert strength.satisfies("minimum", MFA, SMS)
    assert strength.satisfies("maximum", SMS, MFA)
    assert strength.satisfies("better", MFA, SMS)
    # equal contexts never pass "better" or strict "maximum"
    assert not strength.satisfies("better", SMS, SMS)
    assert not strength.satisfies("maximum", MFA, SMS)


def test_alternatives_in_one_request():
    strength = AuthnContextStrength(DIAMOND)
    requested = [SMS, CERT]

    assert strength.satisfies("exact", SMS, requested)
    assert strength.satisfies("exact", CERT, requested)
    # SPEC: with several alternatives, minimum accepts anything at or
    # above any listed floor.
    assert strength.satisfies("minimum", MFA, requested)
    # "better" requires strict strength against every listed reference.
    assert strength.satisfies("better", MFA, requested)
    assert not strength.satisfies("better", SMS, requested)
    # "maximum" accepts anything no stronger than one listed ceiling.
    assert strength.satisfies("maximum", PASSWORD, requested)
    assert not strength.satisfies("maximum", MFA, requested)


def test_cycle_is_rejected_before_use():
    with pytest.raises(AuthnContextStrengthError, match="cycle"):
        AuthnContextStrength({"a": ["b"], "b": ["c"], "c": ["a"]})


def test_malformed_configuration_is_rejected():
    with pytest.raises(AuthnContextStrengthError):
        AuthnContextStrength({"a": [1]})
    with pytest.raises(AuthnContextStrengthError):
        AuthnContextStrength([1, 2])


def test_config_rejects_cycle_on_load():
    config = {
        "entityid": "urn:example:sp",
        "authn_context_strength": {"a": ["b"], "b": ["a"]},
        "service": {"sp": {"endpoints": {"assertion_consumer_service": ["http://sp.example/"]}}},
    }
    with pytest.raises(AuthnContextStrengthError, match="cycle"):
        SPConfig().load(config)


# -- broker selection -------------------------------------------------------


def _broker(levels=None):
    broker = AuthnBroker(authn_context_strength=DIAMOND)
    for context, method in (
        (PASSWORD, "password"),
        (SMS, "sms"),
        (CERT, "cert"),
        (MFA, "mfa"),
    ):
        broker.add(authn_context_class_ref(context), method, level=(levels or {}).get(context, 0))
    return broker


def test_broker_exact_keeps_only_the_named_method():
    broker = _broker()

    picked = broker.pick(requested_authn_context(SMS, "exact"))
    assert [method for method, _ in picked] == ["sms"]

    picked = broker.pick(requested_authn_context(MFA, "exact"))
    assert [method for method, _ in picked] == ["mfa"]


def test_broker_never_substitutes_incomparable_methods():
    broker = _broker()

    # Asking for cert exactly must not offer sms.
    assert [m for m, _ in broker.pick(requested_authn_context(CERT, "exact"))] == ["cert"]

    # Asking for at least cert must not offer sms, even though sms is
    # also above the password floor.
    assert [m for m, _ in broker.pick(requested_authn_context(CERT, "minimum"))] == ["cert", "mfa"]


def test_broker_minimum_walks_the_diamond():
    broker = _broker()

    # Both factors plus MFA satisfy the password floor; the password
    # method is the weakest qualifying candidate and comes first.
    picked = broker.pick(requested_authn_context(PASSWORD, "minimum"))
    assert [m for m, _ in picked] == ["password", "sms", "cert", "mfa"]

    # The MFA floor only admits MFA.
    assert [m for m, _ in broker.pick(requested_authn_context(MFA, "minimum"))] == ["mfa"]


def test_broker_better_and_maximum():
    broker = _broker()

    picked = broker.pick(requested_authn_context(PASSWORD, "better"))
    assert [m for m, _ in picked] == ["sms", "cert", "mfa"]

    picked = broker.pick(requested_authn_context(MFA, "maximum"))
    assert [m for m, _ in picked] == ["password", "sms", "cert", "mfa"]


def test_broker_multiple_class_references_have_a_stable_rule():
    broker = _broker()

    # Alternatives are de-duplicated and ordered by strength rank and
    # broker insertion order, regardless of which reference matched.
    picked = broker.pick(requested_authn_context([SMS, CERT], "minimum"))
    assert [m for m, _ in picked] == ["sms", "cert", "mfa"]

    # The request order does not change the candidate order.
    picked = broker.pick(requested_authn_context([CERT, SMS], "minimum"))
    assert [m for m, _ in picked] == ["sms", "cert", "mfa"]


def test_broker_without_configuration_keeps_level_behaviour():
    broker = AuthnBroker()
    for context, method, level in (
        (PASSWORD, "password", 10),
        (SMS, "sms", 20),
        (CERT, "cert", 30),
        (MFA, "mfa", 40),
    ):
        broker.add(authn_context_class_ref(context), method, level=level)

    # The historical integer ordering remains a total order.
    picked = broker.pick(requested_authn_context(SMS, "minimum"))
    assert [m for m, _ in picked] == ["sms", "cert", "mfa"]
    picked = broker.pick(requested_authn_context(SMS, "better"))
    assert [m for m, _ in picked] == ["cert", "mfa"]


# -- session reuse ----------------------------------------------------------


def test_cached_session_is_checked_on_reuse():
    db, name_id = _store([PASSWORD, SMS, CERT])

    assert len(db.get_authn_statements(name_id)) == 3

    requested = requested_authn_context(MFA, "minimum")
    assert db.get_authn_statements(name_id, requested_context=requested) == []

    requested = requested_authn_context(SMS, "exact")
    statements = db.get_authn_statements(name_id, requested_context=requested)
    assert [item[0].authn_context.authn_context_class_ref.text for item in statements] == [SMS]

    requested = requested_authn_context(PASSWORD, "minimum")
    statements = db.get_authn_statements(name_id, requested_context=requested)
    assert [item[0].authn_context.authn_context_class_ref.text for item in statements] == [
        PASSWORD,
        SMS,
        CERT,
    ]


def test_session_index_and_context_must_both_match():
    db, name_id = _store([PASSWORD])

    assert db.get_authn_statements(name_id, session_index="s0") != []
    assert db.get_authn_statements(name_id, session_index="missing") == []
    assert db.get_authn_statements(name_id, session_index="s0", requested_context=requested_authn_context(MFA)) == []


def test_explanation_says_why_an_existing_login_cannot_satisfy_mfa():
    db, name_id = _store([PASSWORD, SMS])

    requested = requested_authn_context(MFA, "minimum")
    explanations = db.explain_authn_statements(name_id, requested_context=requested)

    assert len(explanations) == 2
    for session_index, context, accepted, reason in explanations:
        assert accepted is False
        assert reason
        assert "weaker" in reason or "incomparable" in reason

    # Incomparable methods produce a distinct, explicit reason.
    requested = requested_authn_context(CERT, "minimum")
    explanations = db.explain_authn_statements(name_id, requested_context=requested)
    reasons = {context.authn_context_class_ref.text: reason for _, context, _, reason in explanations}
    assert "incomparable" in reasons[SMS]
    assert "weaker" in reasons[PASSWORD]


def test_context_matches_is_kind_safe():
    strength = AuthnContextStrength(DIAMOND)
    provided = AuthnContext(authn_context_class_ref=AuthnContextClassRef(text=SMS))
    requested = requested_authn_context(SMS, "exact")

    assert context_matches(requested, provided, strength)
    assert not context_matches(requested_authn_context(CERT, "exact"), provided, strength)

    # A declaration reference is not interchangeable with a class
    # reference even if the text is the same.
    decl_requested = requested_authn_context(SMS, "exact")
    decl_requested.authn_context_class_ref = []
    decl_requested.authn_context_decl_ref = [AuthnContextDeclRef(text=SMS)]
    assert not context_matches(decl_requested, provided, strength)


def test_sp_cached_session_is_rechecked():
    from saml2.client import Saml2Client

    sp = Saml2Client(config_file="servera_conf")
    sp.config.setattr("sp", "authn_context_strength", DIAMOND)
    name_id = NameID(text="cached-user")
    sp.users.add_information_about_person(
        {
            "name_id": name_id,
            "issuer": sp.config.entityid,
            "ava": {},
            "not_on_or_after": 10**9,
            "authn_info": [(PASSWORD, [], "2026-11-13T00:00:00Z")],
            "session_index": "s1",
        }
    )

    accepted, reason = sp.cached_session_satisfies(
        name_id, sp.config.entityid, requested_authn_context(MFA, "minimum")
    )
    assert accepted is False
    assert "weaker" in reason

    accepted, reason = sp.cached_session_satisfies(
        name_id, sp.config.entityid, requested_authn_context(PASSWORD, "minimum")
    )
    assert accepted is True
    assert reason == ""


def test_legacy_session_storage_without_configuration_still_accepts():
    db = SessionStorage()
    name_id = NameID(text="subject")
    assertion = Assertion(
        id="a1",
        authn_statement=[_statement(PASSWORD)],
        subject=Subject(name_id=name_id),
    )
    db.store_assertion(assertion, [])

    assert db.get_authn_statements(name_id, requested_context=requested_authn_context(MFA, "minimum")) != []


def test_server_explains_session_reuse():
    with closing(Server(config_file="idp_all_conf")) as idp:
        strength = AuthnContextStrength(DIAMOND)
        idp.authn_context_strength = strength
        idp.session_db.strength = strength

        name_id = idp.ident.transient_nameid("urn:example:sp", "user")
        assertion = Assertion(
            id="stored",
            authn_statement=[_statement(PASSWORD)],
            subject=Subject(name_id=name_id),
        )
        idp.session_db.store_assertion(assertion, [])

        requested = requested_authn_context(MFA, "minimum")
        explanations = idp.explain_authn_statements(assertion.subject, requested_context=requested)
        assert explanations
        assert explanations[0][2] is False
        assert "weaker" in explanations[0][3]

        # The same stored login is accepted for the level it actually reached.
        assert idp.session_db.get_authn_statements(
            name_id, requested_context=requested_authn_context(PASSWORD, "minimum")
        ) != []
