#!/usr/bin/env python3
"""End-to-end demonstration of stateful single logout with local stubs.

Run with::

    .venv/bin/python tests/slo_demo.py

Scenario: one SP portal holds SAML sessions with three IdPs (A, B, C).
During unified logout IdP C temporarily fails; A and B log out. The demo
shows that every participant keeps its own result, that out-of-order and
forged Redirect responses cannot advance the wrong participant, and that a
retry targets only the unfinished party. No real identity platform, network
socket or port is used - all IdPs are in-process stubs (see slo_stubs.py).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from saml2 import BINDING_HTTP_REDIRECT
from saml2.client_base import LogoutError
from saml2.slo import DuplicateLogoutResponse
from saml2.slo import LocalSessionCleaned
from saml2.slo import LogoutResponseMismatch
from saml2.time_util import in_a_while

from slo_stubs import IDP_IDS
from slo_stubs import StubIdPGroup
from slo_stubs import build_sp_client
from slo_stubs import decode_redirect_request


A, B, C = IDP_IDS["A"], IDP_IDS["B"], IDP_IDS["C"]
ALL = [A, B, C]


def banner(title):
    print("\n" + "=" * 72)
    print(title)
    print("=" * 72)


def show(coordinator, note):
    print(f"\n-- {note}")
    for participant in coordinator.state.participants.values():
        short = participant.entity_id.replace("https://", "").replace(".example/", "")
        extra = participant.status_code or participant.error or ""
        print(f"   {short:10s} state={participant.state:18s} attempts={participant.attempts} {extra}")
    unfinished = [p.entity_id for p in coordinator.state.unfinished()]
    print(f"   unfinished={[u.split('.')[0].replace('https://idp-', '') for u in unfinished]} "
          f"complete={coordinator.state.is_complete()}")


def main():
    # ------------------------------------------------------------------ SOAP
    banner("Part 1 - SOAP binding: C times out, A and B log out")
    client, name_id = build_sp_client()
    stub = StubIdPGroup({A: "success", B: "success", C: "timeout"})
    client.send = stub

    try:
        client.do_logout(name_id, ALL, "Tired", in_a_while(minutes=5))
    except LogoutError as exc:
        coordinator = exc.coordinator
        print("do_logout raised LogoutError (legacy contract); state is retained.")
        print("unfinished reported by the exception:",
              [e.split(".")[0].replace("https://idp-", "") for e in exc.unfinished])
        show(coordinator, "after first attempt - A/B done, C timed out")
        print("   local SP session still present:",
              bool(client.users.issuers_of_info(name_id)))

        stub.set_behaviour(C, "success")
        print("\nRetrying only the unfinished participant C...")
        client.retry_logout(name_id, [C])
        show(coordinator, "after retrying C")
        try:
            client.users.issuers_of_info(name_id)
            print("   local SP session: still present (unexpected!)")
        except KeyError:
            print("   local SP session removed only after every participant succeeded.")

    # --------------------------------------------------------------- Redirect
    banner("Part 2 - Redirect binding: out-of-order, forged and duplicate responses")
    client2, name_id2 = build_sp_client()
    stub2 = StubIdPGroup()
    coordinator2 = client2.start_single_logout(
        name_id2, expire=in_a_while(minutes=5), expected_binding=BINDING_HTTP_REDIRECT
    )
    request_ids = {}
    for entity_id in ALL:
        request_ids[entity_id] = decode_redirect_request(
            coordinator2.state.get(entity_id).http_info
        )[0]
    show(coordinator2, "logout requests prepared for all three IdPs")

    # C answers first (out of order).
    coordinator2.process_response(stub2.redirect_response(request_ids[C], C), BINDING_HTTP_REDIRECT)
    show(coordinator2, "C responded first (out of order)")

    # A forged response: A's request id but B's issuer.
    try:
        coordinator2.process_response(
            stub2.redirect_response(request_ids[A], B), BINDING_HTTP_REDIRECT
        )
    except LogoutResponseMismatch as exc:
        print(f"\nForged response rejected (id/issuer mismatch): {exc}")
    show(coordinator2, "no participant advanced due to the forged response")

    # Genuine A response, then a duplicate of it.
    coordinator2.process_response(stub2.redirect_response(request_ids[A], A), BINDING_HTTP_REDIRECT)
    try:
        coordinator2.process_response(stub2.redirect_response(request_ids[A], A), BINDING_HTTP_REDIRECT)
    except DuplicateLogoutResponse:
        print("Duplicate A response ignored; A stays 'succeeded'.")
    show(coordinator2, "A succeeded; duplicate did not change anything")

    # B's response arrives after the local session was cleaned out of band.
    pending_b = stub2.redirect_response(request_ids[B], B)
    client2.local_logout(name_id2)
    try:
        coordinator2.process_response(pending_b, BINDING_HTTP_REDIRECT)
    except LocalSessionCleaned:
        pass
    show(coordinator2, "B response after local session cleaned")

    # ------------------------------------------------------------- final view
    banner("Final participant results")
    for participant in coordinator2.state.participants.values():
        print(f"   {participant.entity_id:28s} -> {participant.state}")
    still_out = [
        p.entity_id.split(".")[0].replace("https://idp-", "")
        for p in coordinator2.state.unfinished()
    ]
    print("\nParticipants still not logged out:", still_out)
    print("Full event trace:")
    for event in coordinator2.state.events:
        print("   -", event)


if __name__ == "__main__":
    main()
