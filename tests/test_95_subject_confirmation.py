#!/usr/bin/env python
"""Security regression tests for bearer / holder-of-key SubjectConfirmation.

These tests exercise the *real* response validation entry point,
``Saml2Client.parse_authn_request_response``: every assertion is built with the
repository's assertion construction helpers and signed with the local IdP
certificate through xmlsec1, so neither the signature verification nor the
subject confirmation checks are mocked.

The security property under test is the *per-candidate* binding of the
``SubjectConfirmationData`` constraints. When several
``SubjectConfirmation`` elements are present, each one must independently
satisfy, for its own confirmation method, the whole constraint set:

* bearer: time window (``NotBefore`` / ``NotOnOrAfter`` incl. clock skew),
  ``Recipient`` matching an SP assertion consumer service, and
  ``InResponseTo`` matching an outstanding request;
* holder-of-key: the bearer time/recipient checks plus a ``KeyInfo`` proving
  possession of the confirming key.

A validator must never assemble a valid login from candidate A's Recipient,
candidate B's validity window and candidate C's InResponseTo.
"""

from base64 import b64decode
from base64 import encodebytes as b64encode

from pytest import raises

from pathutils import full_path

from saml2 import BINDING_HTTP_POST
from saml2 import extension_elements_to_elements
from saml2 import saml
from saml2 import xmldsig as ds
from saml2.assertion import Assertion
from saml2.assertion import Policy
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.client import Saml2Client
from saml2.config import SPConfig
from saml2.response import UnsolicitedResponse
from saml2.response import VerificationError
from saml2.server import Server
from saml2.sigver import SignatureError
from saml2.time_util import a_while_ago
from saml2.time_util import in_a_while
from saml2.validate import ResponseLifetimeExceed
from saml2.validate import ToEarly


SP_ENTITY_ID = "urn:mace:example.com:saml:roland:sp"
ACS_URL = "http://lingon.catalogix.se:8087/"
EVIL_ACS_URL = "http://attacker.example.com/evil-acs"
REQUEST_ID = "id1"
UNKNOWN_REQUEST_ID = "id-unknown"
CAME_FROM = "http://foo.example.com/service"

# server_conf.py sets accepted_time_diff = 60, which becomes the response
# validation clock skew in seconds. Boundary tests stay clearly on one side.
INSIDE_SLACK = 30
OUTSIDE_SLACK = 90

CONV_INFO = {"remote_addr": "127.0.0.1"}
OUTSTANDING_QUERIES = {REQUEST_ID: CAME_FROM}


def _der_certificate():
    """Return the local IdP certificate as single-line DER base64.

    A ``X509Certificate`` inside SubjectConfirmationData must not carry the
    PEM headers/line breaks, otherwise the enveloped signature cannot be
    canonicalised by xmlsec1.
    """
    with open(full_path("test.pem")) as pem_file:
        return "".join(line.strip() for line in pem_file if not line.startswith("-----"))


def bearer_spec(recipient=ACS_URL, in_response_to=REQUEST_ID, not_before=None):
    data = {"recipient": recipient, "in_response_to": in_response_to}
    if not_before is not None:
        data["not_before"] = not_before
    return {"method": saml.SCM_BEARER, "subject_confirmation_data": data}


def holder_of_key_spec(recipient=ACS_URL, in_response_to=REQUEST_ID):
    key_info = ds.KeyInfo(
        x509_data=ds.X509Data(x509_certificate=ds.X509Certificate(text=_der_certificate()))
    )
    return {
        "method": saml.SCM_HOLDER_OF_KEY,
        "key_info": key_info,
        "subject_confirmation_data": {"recipient": recipient, "in_response_to": in_response_to},
    }


class SubjectConfirmationFactory:
    """Builds signed responses with arbitrary SubjectConfirmation candidates.

    The assertion is produced with the same ``Assertion.construct`` /
    ``do_subject`` machinery a real IdP uses, optionally mutated *before*
    signing, and then wrapped and signed by ``Server._response`` with the
    local IdP key. The SP therefore performs the genuine xmlsec1 signature
    verification.
    """

    def __init__(self):
        self.server = Server("idp_conf")
        config = SPConfig()
        config.load_file("server_conf")
        self.client = Saml2Client(config)
        self._policy = Policy(mds=self.server.metadata)

    def close(self):
        self.server.close()

    def _build_assertion(self, specs):
        farg = {"subject": {"subject_confirmation": specs}}
        name_id = self.server.ident.construct_nameid("foba0001@example.com", self._policy, SP_ENTITY_ID, None)
        assertion = Assertion({"mail": ["a@example.com"]})
        assertion.acs = self.server.config.attribute_converters
        return assertion.construct(
            SP_ENTITY_ID,
            self.server.config.attribute_converters,
            self._policy,
            issuer=self.server._issuer(None),
            farg=farg,
            name_id=name_id,
            authn_class=INTERNETPROTOCOLPASSWORD,
        )

    def signed_response(self, specs, mutate_assertion=None):
        assertion = self._build_assertion(specs)
        if mutate_assertion is not None:
            mutate_assertion(assertion)
        response = self.server._response(
            REQUEST_ID,
            ACS_URL,
            None,
            None,
            sign=True,
            to_sign=[],
            sp_entity_id=SP_ENTITY_ID,
            assertion=assertion,
        )
        return b64encode(str(response).encode())

    def parse(self, encoded_response):
        return self.client.parse_authn_request_response(
            encoded_response,
            BINDING_HTTP_POST,
            OUTSTANDING_QUERIES,
            conv_info=CONV_INFO,
        )


class TestSubjectConfirmationSecurity:
    """Per-candidate constraint binding on the real validation entry point."""

    def setup_class(self):
        self.factory = SubjectConfirmationFactory()

    def teardown_class(self):
        self.factory.close()

    def _confirmation_methods(self, response):
        return [
            confirmation.method
            for confirmation in response.response.assertion[0].subject.subject_confirmation
        ]

    def _key_info_count(self, confirmation):
        data = confirmation.subject_confirmation_data
        return len(extension_elements_to_elements(data.extension_elements, [saml, ds]))

    # -- happy path ---------------------------------------------------------

    def test_single_complete_bearer_candidate_is_accepted(self):
        """One bearer candidate satisfying every constraint logs in."""
        response = self.factory.parse(self.factory.signed_response([bearer_spec()]))

        assert response is not None
        assert response.came_from == CAME_FROM
        [confirmation] = response.response.assertion[0].subject.subject_confirmation
        assert confirmation.method == saml.SCM_BEARER
        assert confirmation.subject_confirmation_data.recipient == ACS_URL
        assert confirmation.subject_confirmation_data.in_response_to == REQUEST_ID

    def test_two_complete_bearer_candidates_are_accepted(self):
        """Two independently complete bearer candidates both survive."""
        response = self.factory.parse(
            self.factory.signed_response([bearer_spec(), bearer_spec()])
        )

        assert len(response.response.assertion[0].subject.subject_confirmation) == 2
        assert self._confirmation_methods(response) == [saml.SCM_BEARER, saml.SCM_BEARER]

    # -- cross-candidate splicing: the core regression ----------------------

    def test_constraints_cannot_be_spliced_across_candidates(self):
        """Recipient / time window / InResponseTo must hold on one candidate.

        Candidate 0 has a valid window and InResponseTo but an attacker
        Recipient; candidate 1 has a valid Recipient and InResponseTo but is
        expired; candidate 2 has a valid Recipient and window but an unknown
        InResponseTo. No single candidate satisfies the whole bearer
        constraint set, so the response must be rejected even though every
        individual constraint value exists somewhere in the Subject.
        """

        def expire_second_candidate(assertion):
            assertion.subject.subject_confirmation[1].subject_confirmation_data.not_on_or_after = (
                a_while_ago(seconds=OUTSIDE_SLACK)
            )

        specs = [
            bearer_spec(recipient=EVIL_ACS_URL),
            bearer_spec(),
            bearer_spec(in_response_to=UNKNOWN_REQUEST_ID),
        ]

        with raises(UnsolicitedResponse, match="Unsolicited response"):
            self.factory.parse(self.factory.signed_response(specs, expire_second_candidate))

    def test_splicing_rejection_is_not_caused_by_signature(self):
        """The spliced response above is correctly signed; only constraints fail."""
        def expire_second_candidate(assertion):
            assertion.subject.subject_confirmation[1].subject_confirmation_data.not_on_or_after = (
                a_while_ago(seconds=OUTSIDE_SLACK)
            )

        specs = [
            bearer_spec(recipient=EVIL_ACS_URL),
            bearer_spec(),
            bearer_spec(in_response_to=UNKNOWN_REQUEST_ID),
        ]
        encoded = self.factory.signed_response(specs, expire_second_candidate)

        # Parsing without conv_info still reaches the InResponseTo rejection:
        # the signature verifies, and recipient checks are only skipped
        # because no conversation information is supplied.
        with raises(UnsolicitedResponse):
            self.factory.client.parse_authn_request_response(
                encoded, BINDING_HTTP_POST, OUTSTANDING_QUERIES
            )

    # -- every candidate missing exactly one constraint --------------------

    def test_bearer_missing_recipient_binding_is_rejected(self):
        """Constraint group 'Recipient' fails on the sole bearer candidate."""
        with raises(VerificationError, match="No valid recipient"):
            self.factory.parse(self.factory.signed_response([bearer_spec(recipient=EVIL_ACS_URL)]))

    def test_bearer_expired_not_on_or_after_is_rejected(self):
        """Constraint group 'NotOnOrAfter time window' fails (too old)."""
        def expire(assertion):
            assertion.subject.subject_confirmation[0].subject_confirmation_data.not_on_or_after = (
                a_while_ago(seconds=OUTSIDE_SLACK)
            )

        with raises(ResponseLifetimeExceed, match="too old"):
            self.factory.parse(self.factory.signed_response([bearer_spec()], expire))

    def test_bearer_future_not_before_is_rejected(self):
        """Constraint group 'NotBefore time window' fails (too early)."""
        spec = bearer_spec(not_before=in_a_while(seconds=OUTSIDE_SLACK))

        with raises(ToEarly, match="Can't use response yet"):
            self.factory.parse(self.factory.signed_response([spec]))

    def test_bearer_unknown_in_response_to_is_rejected(self):
        """Constraint group 'InResponseTo / outstanding request' fails."""
        with raises(UnsolicitedResponse, match="Unsolicited response"):
            self.factory.parse(
                self.factory.signed_response([bearer_spec(in_response_to=UNKNOWN_REQUEST_ID)])
            )

    def test_one_bad_candidate_does_not_poison_a_complete_candidate(self):
        """A complete bearer candidate still wins when another one is skipped.

        This pins the intended OR semantics across candidates while the
        splicing test pins the AND semantics within a candidate. The holder
        of-key candidate lacks its mandatory KeyInfo and is therefore
        disqualified on its own, without touching the complete bearer.
        """
        def strip_hok_key_info(assertion):
            assertion.subject.subject_confirmation[1].subject_confirmation_data.extension_elements = []

        response = self.factory.parse(
            self.factory.signed_response([bearer_spec(), holder_of_key_spec()], strip_hok_key_info)
        )

        [confirmation] = response.response.assertion[0].subject.subject_confirmation
        assert confirmation.method == saml.SCM_BEARER
        assert confirmation.subject_confirmation_data.recipient == ACS_URL

    # -- bearer / holder-of-key mixing --------------------------------------

    def test_complete_bearer_and_holder_of_key_candidates_are_accepted(self):
        """A valid bearer and a valid holder-of-key candidate both confirm."""
        response = self.factory.parse(
            self.factory.signed_response([bearer_spec(), holder_of_key_spec()])
        )

        confirmations = response.response.assertion[0].subject.subject_confirmation
        assert [confirmation.method for confirmation in confirmations] == [
            saml.SCM_BEARER,
            saml.SCM_HOLDER_OF_KEY,
        ]
        holder_confirmation = confirmations[1]
        assert self._key_info_count(holder_confirmation) == 1

    def test_holder_of_key_without_key_info_is_rejected(self):
        """Constraint group 'holder-of-key KeyInfo' fails for the only HoK."""
        def strip_key_info(assertion):
            assertion.subject.subject_confirmation[0].subject_confirmation_data.extension_elements = []

        with raises(VerificationError, match="No valid subject confirmation"):
            self.factory.parse(
                self.factory.signed_response([holder_of_key_spec()], strip_key_info)
            )

    def test_keyless_hok_cannot_borrow_bearer_constraints(self):
        """A KeyInfo-less HoK cannot combine with a bearer's other fields.

        Both candidates share Recipient and InResponseTo values, but the
        holder-of-key candidate still lacks its mandatory KeyInfo and the
        bearer candidate is independently invalid (wrong Recipient).
        """
        def strip_key_info(assertion):
            assertion.subject.subject_confirmation[0].subject_confirmation_data.extension_elements = []

        specs = [holder_of_key_spec(), bearer_spec(recipient=EVIL_ACS_URL)]

        with raises(VerificationError, match="No valid (recipient|subject confirmation)"):
            self.factory.parse(self.factory.signed_response(specs, strip_key_info))

    def test_broken_bearers_cannot_block_or_fake_a_complete_hok(self):
        """A KeyInfo-less HoK is dropped while the complete HoK still confirms."""
        def strip_first_hok_key_info(assertion):
            assertion.subject.subject_confirmation[1].subject_confirmation_data.extension_elements = []

        specs = [
            bearer_spec(),
            holder_of_key_spec(),
            holder_of_key_spec(),
        ]

        response = self.factory.parse(self.factory.signed_response(specs, strip_first_hok_key_info))

        kept = response.response.assertion[0].subject.subject_confirmation
        assert [confirmation.method for confirmation in kept] == [
            saml.SCM_BEARER,
            saml.SCM_HOLDER_OF_KEY,
        ]
        assert self._key_info_count(kept[1]) == 1

    # -- clock skew boundary -------------------------------------------------

    def test_expired_within_clock_skew_is_accepted(self):
        """NotOnOrAfter inside the 60 s slack still validates the window."""
        def recent_expiry(assertion):
            assertion.subject.subject_confirmation[0].subject_confirmation_data.not_on_or_after = (
                a_while_ago(seconds=INSIDE_SLACK)
            )

        response = self.factory.parse(
            self.factory.signed_response([bearer_spec()], recent_expiry)
        )
        assert response is not None

    def test_expired_beyond_clock_skew_is_rejected(self):
        """NotOnOrAfter beyond the 60 s slack violates the time window."""
        def old_expiry(assertion):
            assertion.subject.subject_confirmation[0].subject_confirmation_data.not_on_or_after = (
                a_while_ago(seconds=OUTSIDE_SLACK)
            )

        with raises(ResponseLifetimeExceed):
            self.factory.parse(self.factory.signed_response([bearer_spec()], old_expiry))

    def test_future_not_before_within_clock_skew_is_accepted(self):
        """NotBefore inside the slack is tolerated (clocks may drift)."""
        spec = bearer_spec(not_before=in_a_while(seconds=INSIDE_SLACK))

        response = self.factory.parse(self.factory.signed_response([spec]))
        assert response is not None

    def test_future_not_before_beyond_clock_skew_is_rejected(self):
        """NotBefore beyond the slack violates the time window."""
        spec = bearer_spec(not_before=in_a_while(seconds=OUTSIDE_SLACK))

        with raises(ToEarly):
            self.factory.parse(self.factory.signed_response([spec]))

    # -- signature really is being verified ---------------------------------

    def test_tampered_after_signing_fails_signature_verification(self):
        """Mutating signed XML must fail, proving signature checks are live."""
        encoded = self.factory.signed_response([bearer_spec()])
        signed_xml = b64decode(encoded).decode("utf-8")
        assert ACS_URL in signed_xml

        tampered_xml = signed_xml.replace(ACS_URL, EVIL_ACS_URL)
        tampered = b64encode(tampered_xml.encode("utf-8"))

        with raises(SignatureError, match="Failed to verify signature"):
            self.factory.parse(tampered)
