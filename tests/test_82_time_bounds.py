#!/usr/bin/env python
"""Separation of the three SAML time bounds and session lifetime handling.

The response may be *accepted* within a clock-slack window, while the
established session has its own lifetime. These tests pin a fixed clock and
probe both sides of every boundary, and make sure that the two legal
configurations (short assertion / long session and long assertion / short
session) are never conflated.
"""
from contextlib import contextmanager

from pytest import raises

from saml2 import saml
from saml2 import samlp
from saml2 import time_util
from saml2.cache import Cache
from saml2.config import config_factory
from saml2.ident import code
from saml2.population import Population
from saml2.response import authn_response
from saml2.response import VerificationError
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.validate import ResponseLifetimeExceed
from saml2.validate import ToEarly
from pathutils import dotname


SP_ENTITY_ID = "urn:mace:example.com:saml:roland:sp"
ACS_URL = "https://sp.example.com/acs/post"
IDP_ENTITY_ID = "https://idp.example.com"
REQUEST_ID = "id-Wnv7CMQO1pFJoRWgi"
TIMESLACK = 60

# Fixed "now" used by every test through the fixed_clock fixture.
NOW = 1_700_000_000


@contextmanager
def fixed_clock(epoch):
    time_util.set_fixed_clock(epoch)
    try:
        yield
    finally:
        time_util.set_fixed_clock(None)


def iso(epoch):
    return time_util.instant(time_stamp=epoch)


def make_response_xml(
    conditions_nooa=None,
    conditions_nb=None,
    scd_nooa=None,
    scd_nb=None,
    session_nooa=None,
    include_conditions=True,
    include_session_bound=True,
):
    """Build a bearer AuthnResponse XML string with the given time bounds."""
    issuer = saml.Issuer(text=IDP_ENTITY_ID)
    name_id = saml.NameID(format=NAMEID_FORMAT_PERSISTENT, text="b8e734571d9adb0e6444a5b49a22f4206df24d88")

    scd_kwargs = {"recipient": ACS_URL, "in_response_to": REQUEST_ID}
    if scd_nooa is not None:
        scd_kwargs["not_on_or_after"] = iso(scd_nooa)
    if scd_nb is not None:
        scd_kwargs["not_before"] = iso(scd_nb)
    subject_confirmation = saml.SubjectConfirmation(
        method=saml.SCM_BEARER,
        subject_confirmation_data=saml.SubjectConfirmationData(**scd_kwargs),
    )
    subject = saml.Subject(name_id=name_id, subject_confirmation=[subject_confirmation])

    conditions = None
    if include_conditions:
        conditions = saml.Conditions(
            not_before=iso(conditions_nb if conditions_nb is not None else NOW - 60),
            audience_restriction=[
                saml.AudienceRestriction(audience=[saml.Audience(text=SP_ENTITY_ID)])
            ],
        )
        if conditions_nooa is not None:
            conditions.not_on_or_after = iso(conditions_nooa)

    authn_kwargs = {
        "authn_instant": iso(NOW - 10),
        "session_index": "_session-index-1",
        "authn_context": saml.AuthnContext(
            authn_context_class_ref=saml.AuthnContextClassRef(
                text="urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
            )
        ),
    }
    if include_session_bound and session_nooa is not None:
        authn_kwargs["session_not_on_or_after"] = iso(session_nooa)
    authn_statement = saml.AuthnStatement(**authn_kwargs)

    assertion = saml.Assertion(
        issuer=issuer,
        subject=subject,
        conditions=conditions,
        authn_statement=[authn_statement],
        version="2.0",
        id="assertion-id-1",
        issue_instant=iso(NOW),
    )
    response = samlp.Response(
        issuer=issuer,
        version="2.0",
        id="response-id-1",
        issue_instant=iso(NOW),
        in_response_to=REQUEST_ID,
        destination=ACS_URL,
        assertion=[assertion],
        status=samlp.Status(status_code=samlp.StatusCode(value=samlp.STATUS_SUCCESS)),
    )
    return response.to_string().decode("utf-8")


def make_parser(timeslack=TIMESLACK):
    conf = config_factory("sp", dotname("server_conf"))
    conf.only_use_keys_in_metadata = False
    return authn_response(
        conf,
        ACS_URL,
        outstanding_queries={REQUEST_ID: "http://localhost:8088/sso"},
        timeslack=timeslack,
        asynchop=True,
        allow_unsolicited=False,
    )


def parse(xml, timeslack=TIMESLACK):
    parser = make_parser(timeslack)
    parser.loads(xml, decode=False)
    parser.verify()
    return parser


# ---------------------------------------------------------------------------
# Fixed clock plumbing
# ---------------------------------------------------------------------------


def test_fixed_clock_is_observed_by_time_helpers():
    with fixed_clock(NOW):
        assert time_util.utc_now() == NOW
        assert time_util.utc_time_sans_frac() == NOW
        assert time_util.time_in_a_while(seconds=5).timestamp() == NOW + 5
        assert time_util.time_a_while_ago(seconds=5).timestamp() == NOW - 5
        assert time_util.before(iso(NOW + 1)) is True
        assert time_util.before(iso(NOW)) is True
        assert time_util.after(iso(NOW)) is False
        assert time_util.after(iso(NOW - 1)) is True
    assert time_util.utc_now() != NOW


def test_to_epoch_normalizes_all_time_shapes():
    struct = time_util.str_to_time(iso(NOW))
    assert time_util.to_epoch(iso(NOW)) == NOW
    assert time_util.to_epoch(struct) == NOW
    assert time_util.to_epoch(NOW) == NOW
    assert time_util.to_epoch(0) == 0
    assert time_util.to_epoch(None) is None
    assert time_util.to_epoch("") == ""


# ---------------------------------------------------------------------------
# Boundary samples: acceptance window vs. stored bound
# ---------------------------------------------------------------------------


def test_conditions_boundary_accepted_exactly_at_limit():
    xml = make_response_xml(conditions_nooa=NOW, scd_nooa=NOW + 300, session_nooa=NOW + 7200)
    with fixed_clock(NOW):
        resp = parse(xml)
    # the stored bound is the raw timestamp, no slack added
    assert resp.assertion_not_on_or_after == NOW
    assert resp.not_on_or_after == NOW


def test_conditions_one_second_past_limit_rejected_without_slack():
    xml = make_response_xml(conditions_nooa=NOW - 1, scd_nooa=NOW + 300, session_nooa=NOW + 7200)
    with fixed_clock(NOW):
        with raises((ResponseLifetimeExceed, VerificationError)):
            parse(xml, timeslack=0)


def test_conditions_slack_allows_acceptance_but_does_not_extend_stored_bound():
    # Expired TIMESLACK seconds ago: still acceptable thanks to the slack...
    xml = make_response_xml(
        conditions_nooa=NOW - TIMESLACK, scd_nooa=NOW + 300, session_nooa=NOW + 7200
    )
    with fixed_clock(NOW):
        resp = parse(xml)
    # ...but the recorded assertion bound keeps its original value and must
    # not gain TIMESLACK extra seconds of (session) life.
    assert resp.assertion_not_on_or_after == NOW - TIMESLACK
    assert resp.session_expiration() == NOW - TIMESLACK


def test_conditions_one_second_beyond_slack_rejected():
    xml = make_response_xml(
        conditions_nooa=NOW - TIMESLACK - 1, scd_nooa=NOW + 300, session_nooa=NOW + 7200
    )
    with fixed_clock(NOW):
        with raises((ResponseLifetimeExceed, VerificationError)):
            parse(xml)


def test_subject_confirmation_boundary_accepted_exactly_at_limit():
    xml = make_response_xml(conditions_nooa=NOW + 3600, scd_nooa=NOW, session_nooa=NOW + 7200)
    with fixed_clock(NOW):
        resp = parse(xml)
    assert resp.subject_confirmation_not_on_or_after == NOW


def test_subject_confirmation_one_second_past_rejected_without_slack():
    xml = make_response_xml(conditions_nooa=NOW + 3600, scd_nooa=NOW - 1, session_nooa=NOW + 7200)
    with fixed_clock(NOW):
        with raises(ResponseLifetimeExceed):
            parse(xml, timeslack=0)


def test_subject_confirmation_slack_accepts_without_extending_bound():
    xml = make_response_xml(
        conditions_nooa=NOW + 3600, scd_nooa=NOW - TIMESLACK, session_nooa=NOW + 7200
    )
    with fixed_clock(NOW):
        resp = parse(xml)
    assert resp.subject_confirmation_not_on_or_after == NOW - TIMESLACK


def test_subject_confirmation_not_before_boundary():
    xml = make_response_xml(
        conditions_nooa=NOW + 3600,
        scd_nooa=NOW + 300,
        scd_nb=NOW,
        session_nooa=NOW + 7200,
    )
    with fixed_clock(NOW):
        # NotBefore == now is acceptable
        resp = parse(xml)
        assert resp.subject_confirmation_not_on_or_after == NOW + 300

    xml_future = make_response_xml(
        conditions_nooa=NOW + 3600,
        scd_nooa=NOW + 300,
        scd_nb=NOW + 1,
        session_nooa=NOW + 7200,
    )
    with fixed_clock(NOW):
        with raises(ToEarly):
            parse(xml_future, timeslack=0)


def test_three_bounds_are_recorded_independently():
    xml = make_response_xml(
        conditions_nooa=NOW + 3600,
        scd_nooa=NOW + 300,
        session_nooa=NOW + 7200,
    )
    with fixed_clock(NOW):
        resp = parse(xml)
    assert resp.assertion_not_on_or_after == NOW + 3600
    assert resp.subject_confirmation_not_on_or_after == NOW + 300
    assert resp.session_not_on_or_after == NOW + 7200


# ---------------------------------------------------------------------------
# Session lifetime: the two legal configurations must stay distinct
# ---------------------------------------------------------------------------


def test_short_assertion_long_session_session_dies_with_assertion():
    # Short-lived assertion (1h), long-lived session intended (8h). The
    # assertion may no longer be usable, so the session cannot outlive it.
    xml = make_response_xml(
        conditions_nooa=NOW + 3600,
        scd_nooa=NOW + 300,
        session_nooa=NOW + 8 * 3600,
    )
    with fixed_clock(NOW):
        resp = parse(xml)
        assert resp.session_not_on_or_after == NOW + 8 * 3600
        assert resp.assertion_not_on_or_after == NOW + 3600
        assert resp.session_expiration() == NOW + 3600
        assert resp.session_info()["not_on_or_after"] == NOW + 3600


def test_long_assertion_short_session_session_dies_with_authn_statement():
    # Long-lived assertion (8h), short-lived session (1h). The session
    # expires on the AuthnStatement bound even though the assertion lasts.
    xml = make_response_xml(
        conditions_nooa=NOW + 8 * 3600,
        scd_nooa=NOW + 300,
        session_nooa=NOW + 3600,
    )
    with fixed_clock(NOW):
        resp = parse(xml)
        assert resp.session_not_on_or_after == NOW + 3600
        assert resp.assertion_not_on_or_after == NOW + 8 * 3600
        assert resp.session_expiration() == NOW + 3600
        assert resp.session_info()["not_on_or_after"] == NOW + 3600


def test_the_two_configurations_are_not_conflated():
    short_assertion = make_response_xml(
        conditions_nooa=NOW + 3600, scd_nooa=NOW + 300, session_nooa=NOW + 8 * 3600
    )
    short_session = make_response_xml(
        conditions_nooa=NOW + 8 * 3600, scd_nooa=NOW + 300, session_nooa=NOW + 3600
    )
    with fixed_clock(NOW):
        first = parse(short_assertion)
        second = parse(short_session)
    # Same effective session end in this case, but the contributing bounds
    # differ and must remain observable.
    assert first.session_expiration() == second.session_expiration() == NOW + 3600
    assert first.assertion_not_on_or_after != second.assertion_not_on_or_after
    assert first.session_not_on_or_after != second.session_not_on_or_after
    assert (
        first.assertion_not_on_or_after == NOW + 3600
        and first.session_not_on_or_after == NOW + 8 * 3600
    )
    assert (
        second.assertion_not_on_or_after == NOW + 8 * 3600
        and second.session_not_on_or_after == NOW + 3600
    )


def test_missing_session_bound_falls_back_to_assertion_bound():
    xml = make_response_xml(
        conditions_nooa=NOW + 3600, scd_nooa=NOW + 300, include_session_bound=False
    )
    with fixed_clock(NOW):
        resp = parse(xml)
    assert resp.session_not_on_or_after == 0
    assert resp.session_expiration() == NOW + 3600
    assert resp.session_info()["not_on_or_after"] == NOW + 3600


def test_missing_all_bounds_does_not_become_permanent_session():
    xml = make_response_xml(
        include_conditions=False,
        scd_nooa=None,
        include_session_bound=False,
    )
    with fixed_clock(NOW):
        resp = parse(xml)
    assert resp.assertion_not_on_or_after == 0
    assert resp.session_not_on_or_after == 0
    assert resp.subject_confirmation_not_on_or_after == 0
    # No evidence-backed bound means the session is not granted any lifetime.
    assert resp.session_expiration() == 0
    assert resp.session_info()["not_on_or_after"] == 0


def test_conflicting_bounds_use_earliest_evidence():
    # Session bound earlier than the assertion bound: earliest wins.
    xml = make_response_xml(
        conditions_nooa=NOW + 7200, scd_nooa=NOW + 300, session_nooa=NOW + 600
    )
    with fixed_clock(NOW):
        resp = parse(xml)
    assert resp.session_expiration() == NOW + 600


def test_slack_accepted_response_does_not_create_extra_session_life():
    # The assertion expired TIMESLACK seconds ago and is only still
    # acceptable because of the clock slack. The session it establishes must
    # carry the original bound, not bound + slack.
    xml = make_response_xml(
        conditions_nooa=NOW - TIMESLACK,
        scd_nooa=NOW + 300,
        session_nooa=NOW + 7200,
    )
    with fixed_clock(NOW):
        resp = parse(xml)
        expiration = resp.session_info()["not_on_or_after"]
    assert expiration == NOW - TIMESLACK
    # slack must never appear as added lifetime
    assert expiration != NOW - TIMESLACK + TIMESLACK
    with fixed_clock(NOW):
        # and, observed through the cache, the session is already unusable
        population = Population()
        population.add_information_about_person({**resp.session_info(), "ava": {"x": ["y"]}})
        assert population.stale_sources_for_person(resp.name_id) == [IDP_ENTITY_ID]


def test_cache_write_and_read_share_one_time_interpretation():
    cache = Cache()
    with fixed_clock(NOW):
        # written while the clock is pinned at NOW
        cache.set(_name_id(), IDP_ENTITY_ID, {"ava": {}}, NOW + 10)
    # moving the clock past the bound must expire it on read; the stored
    # value cannot be re-interpreted under a different (e.g. local) time scale
    with fixed_clock(NOW + 11):
        assert cache.active(_name_id(), IDP_ENTITY_ID) is False
    with fixed_clock(NOW + 5):
        assert cache.active(_name_id(), IDP_ENTITY_ID) is True


# ---------------------------------------------------------------------------
# Cache: one time interpretation on read and write, fixed-clock driven
# ---------------------------------------------------------------------------


def _name_id():
    return saml.NameID(format=NAMEID_FORMAT_PERSISTENT, text="subject-1")


def test_cache_normalizes_struct_time_to_epoch():
    cache = Cache()
    bound_struct = time_util.str_to_time(iso(NOW + 3600))
    with fixed_clock(NOW):
        cache.set(_name_id(), IDP_ENTITY_ID, {"ava": {"mail": ["a@example.com"]}}, bound_struct)
        info = cache.get(_name_id(), IDP_ENTITY_ID)
        assert info["ava"] == {"mail": ["a@example.com"]}
        assert cache.active(_name_id(), IDP_ENTITY_ID) is True
    # stored form is an epoch int, not a struct_time
    stored = cache._db[code(_name_id())][IDP_ENTITY_ID]
    assert stored[0] == NOW + 3600
    assert isinstance(stored[0], int)


def test_cache_expires_at_exact_boundary_under_fixed_clock():
    cache = Cache()
    with fixed_clock(NOW):
        cache.set(_name_id(), IDP_ENTITY_ID, {"ava": {}}, NOW + 100)
        assert cache.active(_name_id(), IDP_ENTITY_ID) is True
    # one instant before the boundary is still valid
    with fixed_clock(NOW + 99):
        assert cache.active(_name_id(), IDP_ENTITY_ID) is True
    # the NotOnOrAfter instant itself is inclusive ("on or after")
    with fixed_clock(NOW + 100):
        assert cache.active(_name_id(), IDP_ENTITY_ID) is True
    # one instant past the boundary it is definitively expired
    with fixed_clock(NOW + 101):
        assert cache.active(_name_id(), IDP_ENTITY_ID) is False
        from saml2.cache import TooOld

        with raises(TooOld):
            cache.get(_name_id(), IDP_ENTITY_ID)


def test_cache_roundtrip_through_population_uses_session_expiration():
    population = Population()
    xml = make_response_xml(
        conditions_nooa=NOW + 3600,
        scd_nooa=NOW + 300,
        session_nooa=NOW + 8 * 3600,
    )
    with fixed_clock(NOW):
        resp = parse(xml)
        session_info = resp.session_info()
        # the SP may learn attributes out of band; what matters here is the
        # expiry timestamp carried alongside the session info
        session_info["ava"] = {"mail": ["a@example.com"]}
        population.add_information_about_person(session_info)
        name_id = resp.name_id
        assert population.get_identity(name_id)[0] == {"mail": ["a@example.com"]}
        assert population.stale_sources_for_person(name_id) == []
    # session ended at the assertion bound; the inclusive boundary still
    # works, one instant later the source is stale
    with fixed_clock(NOW + 3600):
        assert population.stale_sources_for_person(name_id) == []
    with fixed_clock(NOW + 3601):
        identity, inactive = population.get_identity(name_id)
        assert identity == {}
        assert inactive == [IDP_ENTITY_ID]
        assert population.stale_sources_for_person(name_id) == [IDP_ENTITY_ID]
