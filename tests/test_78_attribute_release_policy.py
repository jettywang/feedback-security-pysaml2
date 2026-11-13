"""Tests for the unified, explainable attribute release decision.

These tests pin down the security properties of the IdP release decision:

* local restrictions and entity categories always win over remote requests;
* FriendlyName / formal Name conflicts and duplicate NameFormats cannot be
  merged into a second, unrestricted path;
* empty values are distinct from absent attributes;
* an SP upgrading an optional attribute to required can at most cause an
  explicit rejection, never a release of locally forbidden data;
* the explanation never contains the raw values that were filtered out.
"""

import re

from pytest import raises

from pathutils import full_path

from saml2 import config
from saml2.attribute_converter import ac_factory
from saml2.assertion import Policy
from saml2.attribute_policy import REASON_MISSING_ATTRIBUTE
from saml2.attribute_policy import REASON_NOT_ALLOWED_LOCAL
from saml2.attribute_policy import REASON_NOT_REQUESTED
from saml2.attribute_policy import REASON_EMPTY_ATTRIBUTE
from saml2.mdstore import MetadataStore
from saml2.s_utils import MissingValue
from saml2.saml import NAME_FORMAT_URI
from saml2.saml import NAME_FORMAT_UNSPECIFIED


URI = NAME_FORMAT_URI
UNSPEC = NAME_FORMAT_UNSPECIFIED
MAIL_OID = "urn:oid:0.9.2342.19200300.100.1.3"
GN_OID = "urn:oid:2.5.4.42"
SN_OID = "urn:oid:2.5.4.4"

SP_ENTITY_ID = "https://release.example.org/sp"
FORBIDDEN_MAIL = "secret@forbidden.example"
ALLOWED_MAIL = "derek@allowed.example"

ATTRCONV = ac_factory(full_path("attributemaps"))


def _requested(name, friendly=None, name_format=URI, required=False, values=None):
    requested = {"name": name, "name_format": name_format}
    if friendly is not None:
        requested["friendly_name"] = friendly
    if required:
        requested["is_required"] = "true"
    if values:
        requested["attribute_value"] = [{"text": value} for value in values]
    return requested


def _policy(restrictions=None, fail_on_missing_requested=True):
    conf = {"default": {"fail_on_missing_requested": fail_on_missing_requested}}
    if restrictions is not None:
        conf["default"]["attribute_restrictions"] = restrictions
    policy = Policy(conf)
    policy.acs = ATTRCONV
    return policy


def _metadata_store(version):
    store = MetadataStore(ATTRCONV, config.Config(), disable_ssl_certificate_validation=True)
    store.imp(
        [
            {
                "class": "saml2.mdstore.MetaDataFile",
                "metadata": [(full_path(f"entity_release_{version}_sp.xml"),)],
            }
        ]
    )
    return store


def test_explanation_counts_values_without_revealing_them():
    policy = _policy({"mail": [re.compile(r".*@allowed\.example$")]})
    ava = {"mail": [FORBIDDEN_MAIL, "also-secret@forbidden.example"]}

    decision = policy.decide(ava, SP_ENTITY_ID, required=[_requested(MAIL_OID, "mail", required=True)])

    explanation = decision.explanation()
    assert explanation["filtered"] == {"mail": {REASON_NOT_ALLOWED_LOCAL: 2}}
    assert explanation["released"] == {}
    assert FORBIDDEN_MAIL not in str(explanation)
    assert "forbidden" not in str(explanation)
    assert not decision.is_satisfied()


def test_required_attribute_withheld_raises_explicit_missing_value():
    policy = _policy({"mail": [re.compile(r".*@allowed\.example$")]})
    ava = {"mail": [FORBIDDEN_MAIL]}

    with raises(MissingValue) as exc_info:
        policy.filter(ava, SP_ENTITY_ID, required=[_requested(MAIL_OID, "mail", required=True)])

    message = str(exc_info.value)
    assert "mail" in message
    assert FORBIDDEN_MAIL not in message


def test_friendly_name_cannot_override_formal_name():
    # The formal Name maps to givenName; the FriendlyName claims "mail".
    # The forbidden mail value must never be released through this conflict.
    policy = _policy({"mail": [re.compile(r".*@allowed\.example$")], "givenName": None})
    ava = {"mail": [FORBIDDEN_MAIL], "givenName": ["Derek"]}

    decision = policy.decide(
        ava, SP_ENTITY_ID, required=[_requested(GN_OID, "mail", required=True)]
    )

    assert "mail" not in decision.allowed
    assert decision.allowed == {"givenName": ["Derek"]}
    assert decision.is_satisfied()


def test_same_attribute_under_two_name_formats_merges_into_one_decision():
    policy = _policy({"mail": [re.compile(r".*@allowed\.example$")]})
    ava = {"mail": [FORBIDDEN_MAIL]}

    decision = policy.decide(
        ava,
        SP_ENTITY_ID,
        required=[
            _requested(MAIL_OID, "mail", URI, required=True),
            _requested("mail", None, UNSPEC, required=True),
        ],
    )

    assert decision.allowed == {}
    assert len(decision.missing) == 1
    assert decision.missing[0]["attribute"] == "mail"


def test_empty_value_is_distinct_from_absent_attribute():
    policy = _policy()

    empty = policy.decide(
        {"mail": []}, SP_ENTITY_ID, required=[_requested(MAIL_OID, "mail", required=True)]
    )
    absent = policy.decide(
        {"givenName": ["Derek"]},
        SP_ENTITY_ID,
        required=[_requested(MAIL_OID, "mail", required=True)],
    )

    assert empty.missing[0]["reason"] == REASON_EMPTY_ATTRIBUTE
    assert absent.missing[0]["reason"] == REASON_MISSING_ATTRIBUTE


def test_remote_request_cannot_widen_local_allow_list():
    # sn is requested but the local allow-list does not contain it.
    policy = _policy({"givenName": None, "mail": None})
    ava = {"givenName": ["Derek"], "mail": [ALLOWED_MAIL], "sn": ["Jeter"]}

    decision = policy.decide(
        ava,
        SP_ENTITY_ID,
        required=[_requested(GN_OID, "givenName", required=True)],
        optional=[_requested(SN_OID, "sn"), _requested(MAIL_OID, "mail")],
    )

    assert set(decision.allowed) == {"givenName", "mail"}
    assert "sn" not in decision.allowed
    assert decision.filtered["sn"] == {REASON_NOT_ALLOWED_LOCAL: 1}


def test_unrequested_attributes_are_withheld_when_remote_request_present():
    policy = _policy()
    ava = {"givenName": ["Derek"], "mail": [ALLOWED_MAIL]}

    decision = policy.decide(
        ava, SP_ENTITY_ID, required=[_requested(GN_OID, "givenName", required=True)]
    )

    assert decision.allowed == {"givenName": ["Derek"]}
    assert decision.filtered["mail"] == {REASON_NOT_REQUESTED: 1}


def test_requested_value_enumeration_only_narrows_result():
    policy = _policy()
    ava = {"givenName": ["Derek", "Ryan"]}

    decision = policy.decide(
        ava,
        SP_ENTITY_ID,
        required=[_requested(GN_OID, "givenName", required=True, values=["Ryan"])],
    )

    assert decision.allowed == {"givenName": ["Ryan"]}
    assert FORBIDDEN_MAIL not in str(decision.explanation())


def test_fail_on_missing_requested_false_keeps_decision_non_raising():
    policy = _policy(fail_on_missing_requested=False)
    ava = {"givenName": ["Derek"]}

    decision = policy.decide(
        ava, SP_ENTITY_ID, required=[_requested(MAIL_OID, "mail", required=True)]
    )
    result = policy.filter(
        ava, SP_ENTITY_ID, required=[_requested(MAIL_OID, "mail", required=True)]
    )

    # No exception is raised by filter; the unrequested givenName is still
    # withheld because the SP only asked for mail.
    assert result == {}
    assert decision.missing == []


def test_same_identity_two_sp_metadata_versions():
    identity = {
        "givenName": ["Derek"],
        "mail": [ALLOWED_MAIL, FORBIDDEN_MAIL],
        "sn": ["Jeter"],
    }
    # Local policy: givenName and mail (only allowed domain) releasable; sn is
    # not on the local allow-list at all.
    restrictions = {
        "givenName": None,
        "mail": [re.compile(r".*@allowed\.example$")],
    }
    policy = _policy(restrictions)

    # ---- SP metadata v1: mail optional, givenName required -----------------
    store_v1 = _metadata_store("v1")
    req_v1 = store_v1.attribute_requirement(SP_ENTITY_ID)
    decision_v1 = policy.decide(
        identity,
        SP_ENTITY_ID,
        required=req_v1["required"],
        optional=req_v1["optional"],
    )

    # The forbidden mail value is filtered, the allowed one released; v1 asked
    # nothing for sn so it is not released.
    assert decision_v1.allowed["givenName"] == ["Derek"]
    assert decision_v1.allowed["mail"] == [ALLOWED_MAIL]
    assert "sn" not in decision_v1.allowed
    assert decision_v1.is_satisfied()
    assert FORBIDDEN_MAIL not in str(decision_v1.explanation())

    # ---- SP metadata v2: mail upgraded to required, sn newly requested ------
    store_v2 = _metadata_store("v2")
    req_v2 = store_v2.attribute_requirement(SP_ENTITY_ID)
    decision_v2 = policy.decide(
        identity,
        SP_ENTITY_ID,
        required=req_v2["required"],
        optional=req_v2["optional"],
    )

    # The newly requested sn must not widen the local allow-list.
    assert "sn" not in decision_v2.allowed
    assert set(decision_v2.allowed) == {"givenName", "mail"}
    assert decision_v2.allowed["mail"] == [ALLOWED_MAIL]
    # The extra demand produces an explicit, explainable rejection, not data.
    assert not decision_v2.is_satisfied()
    reasons = {(entry["attribute"], entry["reason"]) for entry in decision_v2.missing}
    assert ("sn", REASON_NOT_ALLOWED_LOCAL) in reasons
    assert FORBIDDEN_MAIL not in str(decision_v2.explanation())

    # filter() turns the unfulfilled requirement into a MissingValue rejection.
    with raises(MissingValue):
        policy.filter(
            identity,
            SP_ENTITY_ID,
            required=req_v2["required"],
            optional=req_v2["optional"],
        )


def test_restrict_uses_metadata_requested_attributes_end_to_end():
    store = _metadata_store("v2")
    policy = _policy({"givenName": None, "mail": [re.compile(r".*@allowed\.example$")]})
    policy.metadata_store = store

    decision = policy.decide(
        {"givenName": ["Derek"], "mail": [ALLOWED_MAIL]},
        SP_ENTITY_ID,
        required=store.attribute_requirement(SP_ENTITY_ID)["required"],
    )
    assert set(decision.allowed) == {"givenName", "mail"}
    # sn required by metadata but absent locally -> explicit missing reason
    missing_attrs = {entry["attribute"] for entry in decision.missing}
    assert "sn" in missing_attrs
    assert decision.missing and all(
        entry["reason"] in {REASON_MISSING_ATTRIBUTE, REASON_NOT_ALLOWED_LOCAL}
        for entry in decision.missing
    )
