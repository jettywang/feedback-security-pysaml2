.. _single_logout:

Stateful single logout with several IdPs
========================================

When a portal has SAML sessions with more than one IdP, a unified (single)
logout must keep the result of *each* participant independently. If one IdP
times out or refuses while the others log out, those successes must not be
lost, and the local SP session must stay alive until every participant has
logged out.

The :class:`saml2.slo.SingleLogoutCoordinator` provides a stateful view of the
whole operation. One :class:`~saml2.slo.ParticipantResult` is stored per IdP and
the full :class:`~saml2.slo.LogoutState` is kept on the client (``client.slo_states``),
so the operation survives Redirect/POST round trips and can be resumed or
retried later.

Starting a coordinated logout
-----------------------------

.. code-block:: python

    from saml2.client import Saml2Client

    coordinator = client.start_single_logout(
        name_id,
        reason="User requested logout",
        expire=not_on_or_after,
    )

    for entity_id, participant in coordinator.state.participants.items():
        print(entity_id, participant.state)

Each participant moves through the states exported from :mod:`saml2.slo`:
``pending``, ``in_progress``, ``succeeded``, ``denied``, ``timed_out``,
``failed``, ``unsupported`` and ``local_session_gone``. Only ``succeeded``
removes a participant from ``LogoutState.unfinished()``.

Processing asynchronous responses
----------------------------------

For the HTTP Redirect and POST bindings, feed each incoming LogoutResponse to
the coordinator. A response only advances a participant when its request id,
issuer and the local SP session all match; a response forged from another
participant raises :class:`~saml2.slo.LogoutResponseMismatch` and changes
nothing.

.. code-block:: python

    from saml2.slo import (
        DuplicateLogoutResponse,
        LocalSessionCleaned,
        LogoutResponseMismatch,
    )

    try:
        participant = coordinator.process_response(response, binding)
    except LogoutResponseMismatch:
        ...  # wrong request id or issuer; state is untouched
    except DuplicateLogoutResponse:
        ...  # second response for an already finished participant
    except LocalSessionCleaned:
        ...  # local SP session removed before the response arrived

Timeout, explicit rejection (``SLO_DENIED``), duplicate delivery and a cleaned
local session (``SLO_LOCAL_SESSION_GONE``) are therefore always distinguishable.

Retrying only the unfinished parties
------------------------------------

Successful participants are never re-contacted and their sessions are not
restored. Only retryable states (``timed_out``, ``failed``, ``unsupported`` and
``pending``) are sent a fresh logout request:

.. code-block:: python

    responses = client.retry_logout(name_id)                       # all retryable
    responses = client.retry_logout(name_id, [failing_entity_id])  # one party

The local session is removed by ``finish_local_logout()`` (and automatically at
the end of a fully successful run) only when ``coordinator.state.is_complete()``
is true.

Backward compatible entry points
--------------------------------

``Saml2Client.do_logout`` and ``Saml2Client.handle_logout_response`` keep their
historical signatures and return shapes. Internally they now drive the same
coordinator: on a partial SOAP failure ``do_logout`` still raises
:class:`~saml2.client_base.LogoutError`, but the exception carries the retained
``coordinator``, ``logout_state`` and the list of ``unfinished`` entity ids, and
the expired-deadline tuple ``(0, "504 Gateway Timeout", [], [])`` is unchanged.

A runnable, self-contained demonstration using in-process SOAP/Redirect stubs
(no real identity provider) lives in ``tests/slo_demo.py``.
