"""Stateful single logout (SLO) coordination for an SP with several IdPs.

The legacy :meth:`saml2.client.Saml2Client.do_logout` loop treated a failed
participant as fatal: any IdP already logged out was lost when a later one
timed out or refused, and the caller had no way of retrying just the
remaining parties.

The :class:`SingleLogoutCoordinator` in this module keeps one
:class:`ParticipantResult` per IdP for the whole lifetime of the operation.
Success, failure, rejection, timeout, duplicate delivery and the "local
session already cleaned" condition are all distinct, observable states, so
a caller can drive an asynchronous logout to completion, retry only the
participants that never finished, and never mistake another party's
response for progress on the one it is still waiting for.
"""
import logging
from dataclasses import dataclass
from dataclasses import field
from typing import Optional

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2.client_base import LogoutError
from saml2.ident import code
from saml2.mdstore import locations
from saml2.response import LogoutResponse as LogoutResponseMessage
from saml2.response import StatusError
from saml2.response import StatusRequestDenied
from saml2.samlp import STATUS_REQUEST_DENIED
from saml2.samlp import logout_response_from_string
from saml2.s_utils import decode_base64_and_inflate
from saml2.soap import parse_soap_enveloped_saml_logout_response
from saml2.time_util import not_on_or_after


logger = logging.getLogger(__name__)


# Per-participant lifecycle states -------------------------------------------------

#: A logout request has not been sent yet.
SLO_PENDING = "pending"
#: The request was sent over an asynchronous binding; a response is awaited.
SLO_IN_PROGRESS = "in_progress"
#: A successful LogoutResponse matching the request was received (SOAP)
#: or processed (Redirect/POST).
SLO_SUCCEEDED = "succeeded"
#: The IdP answered with an explicit non-success SAML status.
SLO_DENIED = "denied"
#: The participant could not be reached or did not answer in time.
SLO_TIMED_OUT = "timed_out"
#: A transport/parsing/other error occurred while talking to the participant.
SLO_FAILED = "failed"
#: No usable single logout service is published by the participant.
SLO_UNSUPPORTED = "unsupported"
#: A LogoutResponse arrived after the local SP session had already been
#: removed; the remote state cannot be reconciled from this SP anymore.
SLO_LOCAL_SESSION_GONE = "local_session_gone"

#: States from which a participant may be retried.
RETRYABLE_STATES = frozenset({SLO_TIMED_OUT, SLO_FAILED, SLO_UNSUPPORTED, SLO_PENDING})

#: States that mean the participant's logout attempt has ended (one way or
#: another), so another response for the same request is a duplicate.
TERMINAL_STATES = frozenset(
    {
        SLO_SUCCEEDED,
        SLO_DENIED,
        SLO_TIMED_OUT,
        SLO_FAILED,
        SLO_UNSUPPORTED,
        SLO_LOCAL_SESSION_GONE,
    }
)


# Exceptions -----------------------------------------------------------------------


class SLOError(LogoutError):
    """Base class for the stateful single logout coordination errors."""


class LogoutExpired(SLOError):
    """Raised when the whole operation is started/retried after its expiry."""


class LogoutResponseMismatch(SLOError):
    """A response does not match the request id, issuer or SP session."""


class DuplicateLogoutResponse(SLOError):
    """A second response arrived for a participant that is already terminal."""


class LocalSessionCleaned(SLOError):
    """A response arrived for a request whose local session was removed."""


# Result containers ----------------------------------------------------------------


@dataclass
class ParticipantResult:
    """Everything the SP knows about logging out of *one* IdP."""

    entity_id: str
    state: str = SLO_PENDING
    binding: Optional[str] = None
    location: Optional[str] = None
    request_id: Optional[str] = None
    relay_state: Optional[str] = None
    http_info: Optional[dict] = None
    response: Optional[object] = None
    status_code: Optional[str] = None
    error: Optional[str] = None
    detail: Optional[str] = None
    attempts: int = 0
    history: list = field(default_factory=list)

    @property
    def finished(self) -> bool:
        """True once the participant reached a terminal state."""
        return self.state in TERMINAL_STATES

    @property
    def retryable(self) -> bool:
        """True if :meth:`SingleLogoutCoordinator.retry` will touch it."""
        return self.state in RETRYABLE_STATES

    @property
    def succeeded(self) -> bool:
        return self.state == SLO_SUCCEEDED

    def snapshot(self) -> dict:
        """A compact, JSON-friendly view of the participant's state."""
        return {
            "entity_id": self.entity_id,
            "state": self.state,
            "binding": self.binding,
            "request_id": self.request_id,
            "status_code": self.status_code,
            "error": self.error,
            "attempts": self.attempts,
        }

    def _transition(self, new_state, **changes):
        self.history.append({"state": self.state, "request_id": self.request_id})
        self.state = new_state
        for key, value in changes.items():
            setattr(self, key, value)


@dataclass
class LogoutState:
    """The full, resumable state of one coordinated logout operation."""

    name_id: object
    reason: str = ""
    expire: object = None
    sign: Optional[bool] = None
    sign_alg: Optional[str] = None
    digest_alg: Optional[str] = None
    participants: dict = field(default_factory=dict)
    events: list = field(default_factory=list)

    # -- construction -----------------------------------------------------------

    @classmethod
    def build(cls, client, name_id, entity_ids, reason="", expire=None, sign=None,
              sign_alg=None, digest_alg=None):
        state = cls(
            name_id=name_id,
            reason=reason,
            expire=expire,
            sign=sign,
            sign_alg=sign_alg,
            digest_alg=digest_alg,
        )
        for entity_id in entity_ids:
            state.participants[entity_id] = ParticipantResult(entity_id=entity_id)
        return state

    # -- lookups ----------------------------------------------------------------

    def get(self, entity_id) -> ParticipantResult:
        return self.participants[entity_id]

    def by_request_id(self, request_id) -> Optional[ParticipantResult]:
        for participant in self.participants.values():
            if participant.request_id == request_id:
                return participant
        return None

    def in_states(self, *states) -> list:
        return [p for p in self.participants.values() if p.state in states]

    def unfinished(self) -> list:
        """Participants that have not logged out successfully yet.

        Every non-success state counts as unfinished, including terminal
        failures: the caller still needs to decide about a retry. A
        participant only leaves this list via a successful LogoutResponse.
        """
        return [p for p in self.participants.values() if p.state != SLO_SUCCEEDED]

    def retryable(self) -> list:
        return [p for p in self.participants.values() if p.retryable]

    def succeeded(self) -> list:
        return [p for p in self.participants.values() if p.succeeded]

    def is_complete(self) -> bool:
        """True only when every participant succeeded."""
        return bool(self.participants) and all(
            p.state == SLO_SUCCEEDED for p in self.participants.values()
        )

    def record(self, message, **context):
        event = {"message": message}
        event.update(context)
        self.events.append(event)
        logger.info("SLO %s: %s", context.get("entity_id", "-"), message)

    def snapshot(self) -> dict:
        return {
            "complete": self.is_complete(),
            "unfinished": [p.entity_id for p in self.unfinished()],
            "participants": [p.snapshot() for p in self.participants.values()],
        }


# Coordinator ----------------------------------------------------------------------


class SingleLogoutCoordinator:
    """Drives single logout towards a group of IdPs while keeping every result.

    A coordinator is bound to a :class:`~saml2.client.Saml2Client` and one
    subject. It stores its :class:`LogoutState` on the client so that the
    operation survives across the Redirect/POST round trips, and it never
    removes the local session unless *all* participants succeed.
    """

    def __init__(self, client, name_id, entity_ids=None, reason="", expire=None,
                 sign=None, sign_alg=None, digest_alg=None, state=None):
        self.client = client
        if state is not None:
            self.state = state
        else:
            if entity_ids is None:
                entity_ids = client.users.issuers_of_info(name_id)
            if not not_on_or_after(expire):
                raise LogoutExpired("Logout deadline has already passed")
            self.state = LogoutState.build(
                client,
                name_id,
                entity_ids,
                reason=reason,
                expire=expire,
                sign=sign,
                sign_alg=sign_alg,
                digest_alg=digest_alg,
            )
        self._store()

    # -- persistence ------------------------------------------------------------

    @property
    def _storage_key(self):
        return f"slo::{code(self.state.name_id)}"

    def _store(self):
        self.client.slo_states[self._storage_key] = self.state

    @classmethod
    def resume(cls, client, name_id):
        """Recover a coordinator previously stored for *name_id*."""
        key = cls.storage_key_for(name_id)
        state = client.slo_states.get(key)
        if state is None:
            raise LocalSessionCleaned("No stored logout operation for this session")
        return cls(client, name_id, state=state)

    @staticmethod
    def storage_key_for(name_id):
        coded = name_id if isinstance(name_id, str) else code(name_id)
        return f"slo::{coded}"

    @classmethod
    def get_or_create(
        cls,
        client,
        name_id,
        entity_ids=None,
        reason="",
        expire=None,
        sign=None,
        sign_alg=None,
        digest_alg=None,
    ):
        """Return the ongoing coordinator for the session, or start a new one."""
        existing = client.slo_states.get(cls.storage_key_for(name_id))
        if existing is not None:
            return cls(client, name_id, state=existing)
        if entity_ids is None:
            entity_ids = client.users.issuers_of_info(name_id)
        return cls(
            client,
            name_id,
            entity_ids=entity_ids,
            reason=reason,
            expire=expire,
            sign=sign,
            sign_alg=sign_alg,
            digest_alg=digest_alg,
        )

    # -- public API -------------------------------------------------------------

    def start(self, expected_binding=None):
        """Send (or prepare) a logout request for every pending participant.

        :return: a dict keyed by entity id. For SOAP participants the value
            is the parsed :class:`~saml2.response.LogoutResponse`; for
            Redirect/POST participants it is the ``(binding, http_info)``
            tuple the SP must return to the browser.
        """
        if not not_on_or_after(self.state.expire):
            raise LogoutExpired("Logout deadline has already passed")

        responses = {}
        for participant in list(self.state.participants.values()):
            if participant.state != SLO_PENDING:
                continue
            responses[participant.entity_id] = self._initiate(participant, expected_binding)
        return responses

    def process_response(self, response, binding=BINDING_HTTP_REDIRECT):
        """Apply one asynchronous LogoutResponse to the matching participant.

        *response* is either a parsed
        :class:`~saml2.response.LogoutResponse` or the raw XML/encoded
        string received on *binding*. The response must match the request
        id, the issuer and the SP session; a response belonging to another
        participant never advances any state.

        :return: the updated :class:`ParticipantResult`.
        """
        status_error = None
        try:
            participant, parsed = self._match_response(response, binding)
        except StatusError as exc:
            # The message parsed but its non-success SAML status makes the
            # library raise during verify(); match it to the participant via
            # the response object carried by the exception context instead.
            status_error = exc
            participant, parsed = self._match_failed_response(response, binding)

        if participant.finished:
            self.state.record(
                "duplicate response ignored",
                entity_id=participant.entity_id,
                state=participant.state,
            )
            raise DuplicateLogoutResponse(
                f"LogoutResponse for {participant.entity_id} already in state {participant.state}"
            )

        if not self._local_session_exists():
            participant._transition(SLO_LOCAL_SESSION_GONE, response=parsed)
            self.state.record(
                "local session already cleaned",
                entity_id=participant.entity_id,
            )
            self._drop_legacy_state(participant)
            self._store()
            raise LocalSessionCleaned(
                f"Local session for {participant.entity_id} was removed before the response arrived"
            )

        if status_error is not None:
            denied = isinstance(status_error, StatusRequestDenied)
            participant._transition(
                SLO_DENIED if denied else SLO_FAILED,
                response=parsed,
                status_code=self._status_code_from_element(parsed),
                error=type(status_error).__name__,
                detail=str(status_error),
            )
            self.state.record(
                "logout rejected" if denied else "logout non-success",
                entity_id=participant.entity_id,
                error=type(status_error).__name__,
            )
        else:
            self._apply_status(participant, parsed)
        self._drop_legacy_state(participant)
        self._store()
        self._finish_if_complete()
        return participant

    def retry(self, entity_ids=None, expected_binding=None):
        """Send fresh logout requests to participants that never finished.

        Only participants in a retryable state (timeout, transport failure,
        unsupported or never started) are touched; already succeeded
        participants are left alone and their sessions are never restored.

        :return: the same kind of dict as :meth:`start`.
        """
        if not not_on_or_after(self.state.expire):
            raise LogoutExpired("Logout deadline has already passed")

        targets = self._select(entity_ids)
        responses = {}
        for participant in targets:
            if participant.state == SLO_IN_PROGRESS:
                # The old request is abandoned; its state entry is removed.
                self._drop_legacy_state(participant)
            # Keep the binding the participant already used unless the caller
            # forces another one, so a retry stays on the same transport.
            retry_binding = expected_binding or participant.binding
            participant._transition(
                SLO_PENDING,
                request_id=None,
                relay_state=None,
                http_info=None,
                response=None,
                status_code=None,
                error=None,
                detail=None,
                binding=None,
                location=None,
            )
            responses[participant.entity_id] = self._initiate(participant, retry_binding)
        self._store()
        return responses

    def mark_timed_out(self, entity_id, detail=None):
        """Explicitly mark a participant as timed out without a response."""
        participant = self.state.get(entity_id)
        if participant.finished:
            return participant
        participant._transition(SLO_TIMED_OUT, error="timeout", detail=detail)
        self.state.record("marked timed out", entity_id=entity_id, detail=detail)
        self._drop_legacy_state(participant)
        self._store()
        return participant

    def check_timeouts(self, deadline):
        """Move every still in-progress participant past *deadline* to timeout."""
        changed = []
        for participant in self.state.unfinished():
            if participant.state == SLO_IN_PROGRESS:
                changed.append(self.mark_timed_out(participant.entity_id, detail=f"deadline {deadline}"))
        return changed

    def finish_local_logout(self):
        """Remove the local session, but only if every participant succeeded."""
        if not self.state.is_complete():
            raise SLOError(
                "Refusing local logout: participants not finished: "
                f"{[p.entity_id for p in self.state.unfinished()]}"
            )
        self.client.local_logout(self.state.name_id)
        self.state.record("local session removed")
        self.client.slo_states.pop(self._storage_key, None)
        return True

    # -- internals --------------------------------------------------------------

    def _select(self, entity_ids):
        if entity_ids is None:
            return self.state.retryable()
        chosen = []
        for entity_id in entity_ids:
            participant = self.state.get(entity_id)
            if not participant.retryable:
                raise SLOError(
                    f"Participant {entity_id} is in state {participant.state} and cannot be retried"
                )
            chosen.append(participant)
        return chosen

    def _local_session_exists(self):
        try:
            return bool(self.client.users.issuers_of_info(self.state.name_id))
        except KeyError:
            return False

    def _choose_binding(self, participant, expected_binding=None):
        entity_id = participant.entity_id
        supported = self.client.metadata.single_logout_service(entity_id=entity_id, typ="idpsso")
        if not supported:
            participant._transition(
                SLO_UNSUPPORTED, error="no_slo_service", detail="IdP does not publish a SLO service"
            )
            self.state.record("no SLO service", entity_id=entity_id)
            self._store()
            return None, None, None

        preferred = self.client.config.preferred_binding["single_logout_service"]
        choices = filter(
            None,
            (
                expected_binding,
                *(binding for binding in preferred if binding in supported),
                *supported,
            ),
        )
        binding = next(choices, None)
        if not binding:
            participant._transition(
                SLO_UNSUPPORTED, error="no_supported_binding", detail="No usable SLO binding"
            )
            self.state.record("no supported SLO binding", entity_id=entity_id)
            self._store()
            return None, None, None

        service_info = supported[binding]
        location = next(locations(service_info), None)
        if not location:
            participant._transition(
                SLO_UNSUPPORTED, error="no_slo_location", detail="SLO service has no location"
            )
            self.state.record("SLO service without location", entity_id=entity_id)
            self._store()
            return None, None, None

        return binding, location, supported

    def _session_indexes(self, entity_id):
        try:
            session_info = self.client.users.get_info_from(self.state.name_id, entity_id, False)
        except KeyError:
            return None
        session_index = session_info.get("session_index")
        return [session_index] if session_index else None

    def _initiate(self, participant, expected_binding=None):
        entity_id = participant.entity_id
        binding, location, _supported = self._choose_binding(participant, expected_binding)
        if binding is None:
            return None

        sign = self.state.sign if self.state.sign is not None else self.client.logout_requests_signed
        sign_redirect = sign and binding == BINDING_HTTP_REDIRECT
        sign_post = sign and not sign_redirect
        session_indexes = self._session_indexes(entity_id)

        req_id, request = self.client.create_logout_request(
            location,
            entity_id,
            name_id=self.state.name_id,
            reason=self.state.reason,
            expire=self.state.expire,
            session_indexes=session_indexes,
            sign=sign_post,
            sign_alg=self.state.sign_alg,
            digest_alg=self.state.digest_alg,
        )
        relay_state = self.client._relay_state(req_id)
        http_info = self.client.apply_binding(
            binding,
            str(request),
            location,
            relay_state,
            sign=sign_redirect,
            sigalg=self.state.sign_alg,
        )

        participant.attempts += 1
        participant._transition(
            SLO_IN_PROGRESS,
            binding=binding,
            location=location,
            request_id=req_id,
            relay_state=relay_state,
            http_info=http_info,
        )
        self.state.record(
            "logout request sent",
            entity_id=entity_id,
            binding=binding,
            request_id=req_id,
            attempt=participant.attempts,
        )

        if binding == BINDING_SOAP:
            return self._soap_round_trip(participant, http_info)

        # Asynchronous binding: remember enough to validate the response later.
        self.client.state[req_id] = {
            "entity_id": entity_id,
            "operation": "SLO",
            "entity_ids": list(self.state.participants.keys()),
            "name_id": code(self.state.name_id),
            "reason": self.state.reason,
            "not_on_or_after": self.state.expire,
            "sign": self.state.sign,
            "sign_alg": self.state.sign_alg,
            "slo_state_key": self._storage_key,
        }
        self._store()
        return binding, http_info

    def _soap_round_trip(self, participant, http_info):
        try:
            response = self.client.send(**http_info)
        except Exception as exc:  # network failure: timeout or transport error
            state = SLO_TIMED_OUT if self._is_timeout(exc) else SLO_FAILED
            participant._transition(state, error=type(exc).__name__, detail=str(exc))
            self.state.record(
                "SOAP transport error",
                entity_id=participant.entity_id,
                state=state,
                error=str(exc),
            )
            self._store()
            return None

        if not response or response.status_code != 200:
            participant._transition(
                SLO_FAILED,
                error="bad_status_code",
                detail=str(response.status_code if response else None),
            )
            self.state.record(
                "SOAP non-200 response",
                entity_id=participant.entity_id,
                status_code=response.status_code if response else None,
            )
            self._store()
            return None

        try:
            parsed = self.client.parse_logout_request_response(response.text, BINDING_SOAP)
        except StatusError as exc:
            # A syntactically valid response whose SAML status is not success
            # is rejected during verification; keep the explicit status, do
            # not mistake it for a transport/parse failure.
            denied = isinstance(exc, StatusRequestDenied)
            try:
                raw_element = logout_response_from_string(
                    parse_soap_enveloped_saml_logout_response(response.text)
                )
                status_code = self._status_code_from_element(raw_element)
            except Exception:
                status_code = None
            participant._transition(
                SLO_DENIED if denied else SLO_FAILED,
                status_code=status_code,
                error=type(exc).__name__,
                detail=str(exc),
            )
            self.state.record(
                "logout rejected" if denied else "logout non-success",
                entity_id=participant.entity_id,
                error=type(exc).__name__,
            )
            self._store()
            return None
        except Exception as exc:
            participant._transition(SLO_FAILED, error=type(exc).__name__, detail=str(exc))
            self.state.record("SOAP response parse error", entity_id=participant.entity_id, error=str(exc))
            self._store()
            return None

        try:
            self._validate(parsed, participant.request_id, participant.entity_id)
        except LogoutResponseMismatch as exc:
            participant._transition(SLO_FAILED, error="response_mismatch", detail=str(exc))
            self.state.record("SOAP response mismatch", entity_id=participant.entity_id, error=str(exc))
            self._store()
            return None

        self._apply_status(participant, parsed)
        self._store()
        self._finish_if_complete()
        return parsed

    def _match_response(self, response, binding):
        if isinstance(response, LogoutResponseMessage):
            parsed = response
        else:
            parsed = self.client.parse_logout_request_response(response, binding)

        request_id = parsed.in_response_to
        participant = self.state.by_request_id(request_id)
        if participant is None:
            # Unknown request id: the local state for it is gone.
            raise LocalSessionCleaned(
                f"No outstanding logout request with id {request_id}; local session may be cleaned"
            )

        self._validate(parsed, request_id, participant.entity_id)
        return participant, parsed

    def _match_failed_response(self, response, binding):
        """Match a response whose non-success status aborted verification.

        The XML itself is well formed, so decode it without the status check
        to recover the request id and issuer for participant/issuer matching.
        """
        if isinstance(response, LogoutResponseMessage):
            raw = response
        else:
            if binding == BINDING_SOAP:
                xml_text = parse_soap_enveloped_saml_logout_response(response)
            elif binding == BINDING_HTTP_REDIRECT:
                xml_text = decode_base64_and_inflate(response)
                if isinstance(xml_text, bytes):
                    xml_text = xml_text.decode("utf-8")
            else:
                xml_text = response
            raw = logout_response_from_string(xml_text)

        participant = self.state.by_request_id(raw.in_response_to)
        if participant is None:
            raise LocalSessionCleaned(
                f"No outstanding logout request with id {raw.in_response_to}; "
                "local session may be cleaned"
            )
        self._validate(raw, raw.in_response_to, participant.entity_id)
        return participant, raw

    def _validate(self, parsed, request_id, expected_issuer):
        if parsed.in_response_to != request_id:
            raise LogoutResponseMismatch(
                f"Response id {parsed.in_response_to} does not match request {request_id}"
            )
        issuer = self._issuer_of(parsed)
        if issuer != expected_issuer:
            raise LogoutResponseMismatch(
                f"Issuer {issuer!r} does not match participant {expected_issuer!r}"
            )
        # The per-request state entry of an asynchronous binding is removed
        # once the first matching response is applied; its absence alone is
        # therefore not an error (a duplicate may be on its way). The explicit
        # local-session check in process_response handles a cleaned SP session.
        return True

    @staticmethod
    def _issuer_of(parsed):
        # A verified response.StatusResponse exposes issuer(); a raw samlp
        # element parsed without verification carries an Issuer instance.
        issuer = parsed.issuer
        return issuer() if callable(issuer) else (issuer.text if issuer is not None else "")

    @staticmethod
    def _status_code_from_element(element):
        status = getattr(element, "status", None)
        if status is None or status.status_code is None:
            return None
        code_node = status.status_code
        if code_node.status_code is not None:
            return code_node.status_code.value
        return code_node.value

    def _apply_status(self, participant, parsed):
        try:
            ok = parsed.status_ok()
        except StatusError as exc:
            status_code = self._status_code(parsed)
            denied = (
                isinstance(exc, StatusRequestDenied)
                or status_code == STATUS_REQUEST_DENIED
            )
            participant._transition(
                SLO_DENIED if denied else SLO_FAILED,
                response=parsed,
                status_code=status_code,
                error=type(exc).__name__,
                detail=str(exc),
            )
            self.state.record(
                "logout rejected" if denied else "logout non-success",
                entity_id=participant.entity_id,
                status_code=status_code,
            )
            return

        if not ok:
            participant._transition(
                SLO_FAILED,
                response=parsed,
                status_code=self._status_code(parsed),
                error="status_not_ok",
            )
            self.state.record("logout status not ok", entity_id=participant.entity_id)
            return

        participant._transition(SLO_SUCCEEDED, response=parsed, error=None, detail=None,
                                status_code=self._status_code(parsed))
        self.state.record("logout succeeded", entity_id=participant.entity_id)

    @staticmethod
    def _status_code(parsed):
        """Return the most specific SAML status code (nested code wins)."""
        try:
            code_node = parsed.response.status.status_code
        except AttributeError:
            return None
        # A second-level status code carries the concrete reason.
        if code_node.status_code is not None:
            return code_node.status_code.value
        return code_node.value

    @staticmethod
    def _is_timeout(exc):
        name = type(exc).__name__.lower()
        return "timeout" in name or isinstance(exc, TimeoutError)

    def _drop_legacy_state(self, participant):
        if participant.request_id and participant.request_id in self.client.state:
            legacy = self.client.state[participant.request_id]
            if legacy.get("slo_state_key") == self._storage_key:
                del self.client.state[participant.request_id]

    def _finish_if_complete(self):
        if self.state.is_complete():
            self.finish_local_logout()
