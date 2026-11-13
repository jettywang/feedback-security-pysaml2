"""Stateful single logout coordination tests.

These tests use only in-process SOAP/Redirect test doubles
(see ``slo_stubs.py``); no real IdP, socket or network port is required.
They cover partial failure with per-party retained results, retries of just
the unfinished participants, and the distinction between timeout, explicit
rejection, duplicate responses, mismatched responses and a cleaned local
session.
"""
from pytest import raises

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client_base import LogoutError
from saml2.slo import DuplicateLogoutResponse
from saml2.slo import LocalSessionCleaned
from saml2.slo import LogoutExpired
from saml2.slo import LogoutResponseMismatch
from saml2.slo import SLO_DENIED
from saml2.slo import SLO_FAILED
from saml2.slo import SLO_IN_PROGRESS
from saml2.slo import SLO_LOCAL_SESSION_GONE
from saml2.slo import SLO_SUCCEEDED
from saml2.slo import SLO_TIMED_OUT
from saml2.slo import SingleLogoutCoordinator
from saml2.time_util import a_while_ago
from saml2.time_util import in_a_while

from slo_stubs import IDP_IDS
from slo_stubs import StubIdPGroup
from slo_stubs import build_sp_client
from slo_stubs import decode_redirect_request


A, B, C = IDP_IDS["A"], IDP_IDS["B"], IDP_IDS["C"]
ALL_IDPS = [A, B, C]


def _start_soap(behaviours):
    client, name_id = build_sp_client()
    stub = StubIdPGroup(behaviours)
    client.send = stub
    coordinator = client.start_single_logout(name_id, expire=in_a_while(minutes=5))
    return client, name_id, stub, coordinator


def _start_redirect():
    client, name_id = build_sp_client()
    stub = StubIdPGroup()
    coordinator = client.start_single_logout(
        name_id, expire=in_a_while(minutes=5), expected_binding=BINDING_HTTP_REDIRECT
    )
    request_ids = {}
    for entity_id in ALL_IDPS:
        participant = coordinator.state.get(entity_id)
        assert participant.binding == BINDING_HTTP_REDIRECT
        # The LogoutRequest is issued by the SP and addressed to the IdP.
        request_ids[entity_id], issuer = decode_redirect_request(participant.http_info)
        assert issuer == "https://sp.example/"
    return client, name_id, stub, coordinator, request_ids


class TestSoapPartialLogout:
    def test_retains_each_participant_result(self):
        client, name_id, stub, coordinator = _start_soap(
            {A: "success", B: "success", C: "timeout"}
        )

        assert coordinator.state.get(A).state == SLO_SUCCEEDED
        assert coordinator.state.get(B).state == SLO_SUCCEEDED
        assert coordinator.state.get(C).state == SLO_TIMED_OUT
        assert coordinator.state.get(C).error == "TimeoutError"

        # One failure must not roll back the successful parties.
        assert coordinator.state.get(A).succeeded
        assert coordinator.state.get(B).succeeded
        assert not coordinator.state.is_complete()
        # The local SP session stays alive until everybody succeeds.
        assert client.users.issuers_of_info(name_id) == ALL_IDPS
        assert [p.entity_id for p in coordinator.state.unfinished()] == [C]

    def test_legacy_do_logout_raises_but_keeps_state(self):
        client, name_id, stub, _ = _start_soap(
            {A: "success", B: "success", C: "http_500"}
        )
        with raises(LogoutError) as exc_info:
            client.do_logout(name_id, ALL_IDPS, "Tired", in_a_while(minutes=5))

        assert exc_info.value.unfinished == [C]
        state = exc_info.value.logout_state
        assert state.get(A).succeeded and state.get(B).succeeded
        assert state.get(C).state == SLO_FAILED
        # The coordinator remains resumable from the client.
        resumed = SingleLogoutCoordinator.resume(client, name_id)
        assert resumed.state is state

    def test_retry_only_unfinished_party_succeeds(self):
        client, name_id, stub, coordinator = _start_soap(
            {A: "success", B: "success", C: "timeout"}
        )
        first_request_id = coordinator.state.get(C).request_id

        stub.set_behaviour(C, "success")
        responses = client.retry_logout(name_id, [C])

        # A and B keep their original single attempt; C gets a fresh request.
        assert coordinator.state.get(A).attempts == 1
        assert coordinator.state.get(B).attempts == 1
        assert coordinator.state.get(C).attempts == 2
        assert coordinator.state.get(C).request_id != first_request_id
        assert coordinator.state.is_complete()
        assert set(responses) == set(ALL_IDPS)
        # Only now is the local session removed.
        with raises(KeyError):
            client.users.issuers_of_info(name_id)

    def test_retry_does_not_resurrect_logged_out_sessions(self):
        client, name_id, stub, coordinator = _start_soap(
            {A: "success", B: "success", C: "timeout"}
        )
        stub.set_behaviour(C, "success")
        coordinator.retry()  # no explicit list: only retryable parties
        assert coordinator.state.get(A).attempts == 1
        assert coordinator.state.get(B).attempts == 1
        assert coordinator.state.get(C).state == SLO_SUCCEEDED

    def test_cannot_retry_an_already_succeeded_party(self):
        client, name_id, stub, coordinator = _start_soap(
            {A: "success", B: "success", C: "timeout"}
        )
        from saml2.slo import SLOError

        with raises(SLOError):
            coordinator.retry([A])

    def test_explicit_denial_is_distinct_from_timeout(self):
        client, name_id, stub, coordinator = _start_soap(
            {A: "success", B: "denied", C: "timeout"}
        )
        denied = coordinator.state.get(B)
        timed_out = coordinator.state.get(C)
        assert denied.state == SLO_DENIED
        assert "RequestDenied" in denied.status_code
        assert timed_out.state == SLO_TIMED_OUT
        # A denied party is not retried blindly; its state is terminal.
        assert not denied.retryable
        assert timed_out.retryable

    def test_http_error_is_failed_not_timeout(self):
        client, name_id, stub, coordinator = _start_soap({e: "http_500" for e in ALL_IDPS})
        for entity_id in ALL_IDPS:
            assert coordinator.state.get(entity_id).state == SLO_FAILED
            assert coordinator.state.get(entity_id).error == "bad_status_code"

    def test_never_claims_complete_while_a_party_fails(self):
        client, name_id, stub, coordinator = _start_soap(
            {A: "success", B: "success", C: "denied"}
        )
        assert not coordinator.state.is_complete()
        with raises(Exception):
            coordinator.finish_local_logout()
        assert client.users.issuers_of_info(name_id) == ALL_IDPS


class TestAsyncRedirectResponses:
    def test_out_of_order_responses(self):
        client, name_id, stub, coordinator, request_ids = _start_redirect()

        # C answers first, then A, then B.
        coordinator.process_response(stub.redirect_response(request_ids[C], C), BINDING_HTTP_REDIRECT)
        assert coordinator.state.get(C).succeeded
        assert coordinator.state.get(A).state == SLO_IN_PROGRESS

        coordinator.process_response(stub.redirect_response(request_ids[A], A), BINDING_HTTP_REDIRECT)
        coordinator.process_response(stub.redirect_response(request_ids[B], B), BINDING_HTTP_REDIRECT)

        assert coordinator.state.is_complete()
        with raises(KeyError):
            client.users.issuers_of_info(name_id)

    def test_response_must_match_request_id_issuer_and_session(self):
        client, name_id, stub, coordinator, request_ids = _start_redirect()

        # A's request id but B's issuer: must not advance either party.
        forged = stub.redirect_response(request_ids[A], B)
        with raises(LogoutResponseMismatch):
            coordinator.process_response(forged, BINDING_HTTP_REDIRECT)
        assert coordinator.state.get(A).state == SLO_IN_PROGRESS
        assert coordinator.state.get(B).state == SLO_IN_PROGRESS

        # The genuine responses still work afterwards.
        coordinator.process_response(stub.redirect_response(request_ids[A], A), BINDING_HTTP_REDIRECT)
        coordinator.process_response(stub.redirect_response(request_ids[B], B), BINDING_HTTP_REDIRECT)
        coordinator.process_response(stub.redirect_response(request_ids[C], C), BINDING_HTTP_REDIRECT)
        assert coordinator.state.is_complete()

    def test_duplicate_response_is_distinct_and_ignored(self):
        client, name_id, stub, coordinator, request_ids = _start_redirect()
        response = stub.redirect_response(request_ids[A], A)
        coordinator.process_response(response, BINDING_HTTP_REDIRECT)
        with raises(DuplicateLogoutResponse):
            coordinator.process_response(response, BINDING_HTTP_REDIRECT)
        # State unchanged and the other parties untouched.
        assert coordinator.state.get(A).state == SLO_SUCCEEDED
        assert coordinator.state.get(B).state == SLO_IN_PROGRESS

    def test_denied_redirect_response(self):
        client, name_id, stub, coordinator, request_ids = _start_redirect()
        participant = coordinator.process_response(
            stub.redirect_response(request_ids[B], B, denied=True), BINDING_HTTP_REDIRECT
        )
        assert participant.state == SLO_DENIED
        assert "RequestDenied" in participant.status_code
        assert not coordinator.state.is_complete()

    def test_response_after_local_session_cleaned(self):
        client, name_id, stub, coordinator, request_ids = _start_redirect()
        pending_b = stub.redirect_response(request_ids[B], B)
        # The SP session is removed out of band before B's response arrives.
        client.local_logout(name_id)
        with raises(LocalSessionCleaned):
            coordinator.process_response(pending_b, BINDING_HTTP_REDIRECT)
        assert coordinator.state.get(B).state == SLO_LOCAL_SESSION_GONE

    def test_unknown_request_id_is_local_session_gone(self):
        client, name_id, stub, coordinator, _ = _start_redirect()
        with raises(LocalSessionCleaned):
            coordinator.process_response(
                stub.redirect_response("id-does-not-exist", A), BINDING_HTTP_REDIRECT
            )

    def test_client_handle_logout_response_validates_issuer(self):
        client, name_id, stub, coordinator, request_ids = _start_redirect()
        # The convenience wrapper on the client must reject a forged response.
        with raises(LogoutResponseMismatch):
            client.handle_logout_response(
                client.parse_logout_request_response(
                    stub.redirect_response(request_ids[A], B), BINDING_HTTP_REDIRECT
                )
            )

    def test_client_handle_logout_response_chain_keeps_legacy_tuple(self):
        client, name_id, stub, coordinator, request_ids = _start_redirect()

        def feed(entity_id):
            parsed = client.parse_logout_request_response(
                stub.redirect_response(request_ids[entity_id], entity_id),
                BINDING_HTTP_REDIRECT,
            )
            return client.handle_logout_response(parsed)

        # First two responses keep the chain going with response dicts.
        first = feed(A)
        second = feed(B)
        assert isinstance(first, dict) and isinstance(second, dict)
        assert coordinator.state.get(A).succeeded
        assert coordinator.state.get(B).succeeded

        # The last response completes the logout and returns the legacy tuple.
        final = feed(C)
        assert final == (0, "200 Ok", [("Content-type", "text/html")], [])
        with raises(KeyError):
            client.users.issuers_of_info(name_id)


class TestTimeoutAndExpiry:
    def test_mark_timed_out_and_check_timeouts(self):
        client, name_id, stub, coordinator, request_ids = _start_redirect()
        changed = coordinator.check_timeouts("2026-11-13T10:00:00Z")
        assert {p.entity_id for p in changed} == set(ALL_IDPS)
        assert all(p.state == SLO_TIMED_OUT for p in changed)
        # Marking again is idempotent for an already terminal party.
        again = coordinator.mark_timed_out(A)
        assert again.state == SLO_TIMED_OUT

    def test_start_after_expiry_raises(self):
        client, name_id = build_sp_client()
        with raises(LogoutExpired):
            client.start_single_logout(name_id, expire=a_while_ago(minutes=5))

    def test_legacy_expired_returns_gateway_timeout_tuple(self):
        client, name_id = build_sp_client()
        result = client.do_logout(name_id, ALL_IDPS, "Tired", a_while_ago(minutes=5))
        assert result == (0, "504 Gateway Timeout", [], [])


class TestRetryAcrossBindings:
    def test_midway_retry_keeps_other_participants_intact(self):
        # All three over Redirect; two answer, one is marked timed out and
        # retried with a fresh request while the successes stay untouched.
        client, name_id, stub, coordinator, request_ids = _start_redirect()
        coordinator.process_response(stub.redirect_response(request_ids[A], A), BINDING_HTTP_REDIRECT)
        coordinator.process_response(stub.redirect_response(request_ids[B], B), BINDING_HTTP_REDIRECT)
        coordinator.mark_timed_out(C)

        fresh = coordinator.retry([C])
        new_binding, new_http_info = fresh[C]
        new_request_id, issuer = decode_redirect_request(new_http_info)
        assert new_request_id != request_ids[C]
        assert issuer == "https://sp.example/"
        assert coordinator.state.get(A).attempts == 1
        assert coordinator.state.get(B).attempts == 1

        coordinator.process_response(stub.redirect_response(new_request_id, C), BINDING_HTTP_REDIRECT)
        assert coordinator.state.is_complete()
