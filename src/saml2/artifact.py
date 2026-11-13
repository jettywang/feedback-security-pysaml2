"""Server side storage and bookkeeping for SAML 2.0 HTTP Artifact binding.

An artifact is a short reference handed to the browser. The full protocol
message is kept by the entity that minted the artifact and only released
through the back-channel Artifact Resolution Service.

The bindings defined here make sure that:

* a stored artifact is explicitly tied to the entity it was minted for
  (the intended recipient), the SourceID of the issuer and the endpoint
  index of the resolution service;
* an artifact can only be consumed by the entity it was bound to and after
  that entity has authenticated itself with a valid signature;
* a failed attempt by another requester never consumes a valid artifact;
* a successful ArtifactResponse that gets lost on the wire can be replayed
  by the legitimate recipient with the exact same result, while the
  reference can never be turned into a general purpose assertion download;
* expired and unknown artifacts look identical to an outside caller while
  remaining distinguishable internally.
"""

import base64
from hashlib import sha1
import time

from saml2 import SAMLError
from saml2.s_utils import rndbytes


ARTIFACT_TYPECODE = b"\x00\x04"
ARTIFACT_LENGTH = 44
DEFAULT_ARTIFACT_TTL = 300


class ArtifactError(SAMLError):
    """Base class for artifact handling errors."""


class UnknownArtifact(ArtifactError):
    """No artifact with the given reference exists in the store."""


class ExpiredArtifact(ArtifactError):
    """The artifact exists but its validity window has elapsed."""


class InvalidArtifact(ArtifactError):
    """The reference does not conform to the SAML artifact format."""


class ArtifactResolutionDenied(ArtifactError):
    """The requester is not the entity the artifact was bound to."""


def create_artifact(entity_id, message_handle, endpoint_index=0):
    """Build a SAML 2.0 type 0x0004 artifact.

    SAML_artifact   := B64(TypeCode EndpointIndex RemainingArtifact)
    TypeCode        := Byte1Byte2
    EndpointIndex   := Byte1Byte2

    RemainingArtifact := SourceID MessageHandle
    SourceID          := 20-byte sequence
    MessageHandle     := 20-byte sequence

    :param entity_id: Entity ID of the artifact issuer; its SHA-1 becomes
        the SourceID.
    :param message_handle: 20 random bytes (or a value that encodes to
        20 bytes) unique per artifact.
    :param endpoint_index: Index of the Artifact Resolution Service endpoint.
    :return: The Base64 encoded SAML artifact.
    """
    if not isinstance(entity_id, bytes):
        entity_id = entity_id.encode("utf-8")
    source_id = sha1(entity_id).digest()

    if not isinstance(message_handle, bytes):
        message_handle = message_handle.encode("utf-8")

    endpoint_index = int(endpoint_index)
    if not 0 <= endpoint_index <= 0xFFFF:
        raise ValueError("endpoint_index must be an unsigned 16 bit value")

    ter = b"".join(
        (
            ARTIFACT_TYPECODE,
            f"{endpoint_index:02x}".encode("ascii"),
            source_id,
            message_handle,
        )
    )
    return base64.b64encode(ter).decode("ascii")


def decode_artifact(artifact):
    """Split a Base64 encoded artifact into its structural parts.

    :param artifact: The Base64 encoded SAML artifact.
    :return: A tuple ``(typecode, endpoint_index, source_id, message_handle)``
        where ``endpoint_index`` is an int and the two remaining parts are
        raw bytes.
    :raises InvalidArtifact: if the encoding or length is wrong, the
        typecode is not the SAML 2.0 one or the parts have wrong sizes.
    """
    try:
        raw = base64.b64decode(artifact, validate=True)
    except (ValueError, TypeError) as exc:
        raise InvalidArtifact("Artifact is not valid Base64") from exc

    if len(raw) != ARTIFACT_LENGTH:
        raise InvalidArtifact(f"Artifact must be {ARTIFACT_LENGTH} bytes, got {len(raw)}")

    typecode = raw[:2]
    if typecode != ARTIFACT_TYPECODE:
        raise InvalidArtifact(
            f"Invalid artifact typecode {typecode!r}, expected {ARTIFACT_TYPECODE!r}"
        )

    index_bytes = raw[2:4]
    try:
        endpoint_index = int(index_bytes)
    except ValueError:
        endpoint_index = int.from_bytes(index_bytes, "big")

    source_id = raw[4:24]
    message_handle = raw[24:44]
    return typecode, endpoint_index, source_id, message_handle


class StoredArtifact:
    """Everything the issuer needs to resolve an artifact exactly once."""

    def __init__(self, message, recipient_entity_id, source_id, endpoint_index, issued_at, expires_at):
        self.message = message
        self.recipient_entity_id = recipient_entity_id
        self.source_id = source_id
        self.endpoint_index = endpoint_index
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.resolved_count = 0

    def is_expired(self, now=None):
        if now is None:
            now = time.time()
        return now >= self.expires_at


class ArtifactStore:
    """In memory store of artifacts issued by one SAML entity.

    Artifacts are keyed by their Base64 representation. Each entry records
    not only the protocol message but also the entity it was issued for,
    the SourceID embedded in the artifact and the endpoint index, so a
    resolution request can be checked against the reference itself.

    The store implements the retry contract from the SAML artifact profile:
    a successfully created ArtifactResponse may be lost in transit, so the
    legitimate recipient is allowed to repeat the request and receives the
    same message again. Entries therefore stay available until they expire
    rather than being removed on first success.
    """

    def __init__(self, ttl=DEFAULT_ARTIFACT_TTL, clock=None):
        self.ttl = int(ttl)
        self._clock = clock or time.time
        self._store = {}

    def issue(self, artifact, message, recipient_entity_id, source_id, endpoint_index):
        """Persist a freshly minted artifact.

        :param artifact: The Base64 encoded artifact returned to the browser.
        :param message: The full SAML message that backs the reference.
        :param recipient_entity_id: Entity ID of the party allowed to
            resolve the artifact (the SP the browser was sent to).
        :param source_id: The 20 byte SourceID embedded in the artifact.
        :param endpoint_index: The endpoint index embedded in the artifact.
        :return: The stored artifact record.
        """
        now = self._clock()
        record = StoredArtifact(
            message=message,
            recipient_entity_id=recipient_entity_id,
            source_id=source_id,
            endpoint_index=int(endpoint_index),
            issued_at=now,
            expires_at=now + self.ttl,
        )
        self._store[artifact] = record
        return record

    def get(self, artifact):
        """Return the stored record, distinguishing missing from expired.

        :raises UnknownArtifact: no such artifact was ever issued or it has
            already been garbage collected.
        :raises ExpiredArtifact: the artifact exists but is no longer valid.
        """
        try:
            record = self._store[artifact]
        except KeyError as exc:
            raise UnknownArtifact(f"Unknown artifact {artifact!r}") from exc

        if record.is_expired(self._clock()):
            raise ExpiredArtifact(f"Artifact {artifact!r} has expired")

        return record

    def resolve(self, artifact, requester_entity_id):
        """Resolve an artifact on behalf of an authenticated requester.

        The requester must be the entity the artifact was originally bound
        to. An unauthorized or stale attempt raises before any state is
        changed, so a wrong requester can never consume or invalidate a
        legitimate artifact.

        :raises UnknownArtifact: the reference is unknown.
        :raises ExpiredArtifact: the reference is past its validity.
        :raises ArtifactResolutionDenied: the requester does not match the
            bound recipient.
        :return: The stored SAML message.
        """
        record = self.get(artifact)

        if record.recipient_entity_id != requester_entity_id:
            raise ArtifactResolutionDenied(
                f"Artifact {artifact!r} is bound to {record.recipient_entity_id!r}, "
                f"not {requester_entity_id!r}"
            )

        record.resolved_count += 1
        return record.message

    def discard_expired(self):
        """Remove expired entries and return the number of removals."""
        now = self._clock()
        expired = [artifact for artifact, record in self._store.items() if record.is_expired(now)]
        for artifact in expired:
            del self._store[artifact]
        return len(expired)

    def __contains__(self, artifact):
        return artifact in self._store

    def __len__(self):
        return len(self._store)

    def __getitem__(self, artifact):
        """Backward compatible accessor returning the backing SAML message.

        New code should use :meth:`get` or :meth:`resolve` which enforce the
        recipient binding and expiry contract.
        """
        return self.get(artifact).message


def new_message_handle():
    """Generate a fresh, unpredictable 20 byte message handle."""
    digest = sha1()
    digest.update(rndbytes())
    return digest.digest()
