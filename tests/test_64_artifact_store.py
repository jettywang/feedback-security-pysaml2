"""Unit tests for the in-memory artifact store and artifact codec."""

import base64

import pytest

from saml2.artifact import ARTIFACT_TYPECODE
from saml2.artifact import ArtifactResolutionDenied
from saml2.artifact import ArtifactStore
from saml2.artifact import ExpiredArtifact
from saml2.artifact import InvalidArtifact
from saml2.artifact import UnknownArtifact
from saml2.artifact import create_artifact
from saml2.artifact import decode_artifact
from saml2.artifact import new_message_handle


IDP = "urn:mace:example.com:idp"
SP1 = "urn:mace:example.com:sp1"
SP2 = "urn:mace:example.com:sp2"


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make_artifact(store, clock, recipient=SP1, ttl=300):
    handle = new_message_handle()
    artifact = create_artifact(IDP, handle, 1)
    _typecode, index, source_id, _h = decode_artifact(artifact)
    store.issue(artifact, "message", recipient, source_id, index)
    return artifact


def test_create_and_decode_roundtrip():
    handle = b"a" * 20
    artifact = create_artifact(IDP, handle, 1)
    typecode, index, source_id, decoded_handle = decode_artifact(artifact)

    assert typecode == ARTIFACT_TYPECODE
    assert index == 1
    assert decoded_handle == handle
    assert len(base64.b64decode(artifact)) == 44


def test_endpoint_index_range_is_validated():
    with pytest.raises(ValueError):
        create_artifact(IDP, b"a" * 20, 70000)


@pytest.mark.parametrize("bad", ["not-base64!!!", "AAAAAAAAAAAAAAAAAAAAAA=="])
def test_decode_rejects_malformed(bad):
    with pytest.raises(InvalidArtifact):
        decode_artifact(bad)


def test_wrong_typecode_is_rejected():
    raw = b"\x00\x05" + b"\x00\x01" + b"\x00" * 40
    with pytest.raises(InvalidArtifact):
        decode_artifact(base64.b64encode(raw).decode("ascii"))


def test_resolve_requires_bound_recipient():
    clock = FakeClock()
    store = ArtifactStore(ttl=300, clock=clock)
    artifact = make_artifact(store, clock)

    assert store.resolve(artifact, SP1) == "message"
    with pytest.raises(ArtifactResolutionDenied):
        store.resolve(artifact, SP2)


def test_failed_resolution_does_not_consume_artifact():
    clock = FakeClock()
    store = ArtifactStore(ttl=300, clock=clock)
    artifact = make_artifact(store, clock)

    with pytest.raises(ArtifactResolutionDenied):
        store.resolve(artifact, SP2)

    record = store.get(artifact)
    assert record.resolved_count == 0
    assert store.resolve(artifact, SP1) == "message"
    assert record.resolved_count == 1


def test_retry_returns_same_message_until_expiry():
    clock = FakeClock()
    store = ArtifactStore(ttl=10, clock=clock)
    artifact = make_artifact(store, clock, ttl=10)

    assert store.resolve(artifact, SP1) == "message"
    clock.advance(5)
    assert store.resolve(artifact, SP1) == "message"
    assert store.get(artifact).resolved_count == 2

    clock.advance(6)
    with pytest.raises(ExpiredArtifact):
        store.get(artifact)
    with pytest.raises(ExpiredArtifact):
        store.resolve(artifact, SP1)


def test_unknown_and_expired_are_distinct_exceptions():
    clock = FakeClock()
    store = ArtifactStore(ttl=5, clock=clock)
    artifact = make_artifact(store, clock)
    clock.advance(6)

    with pytest.raises(ExpiredArtifact):
        store.get(artifact)
    with pytest.raises(UnknownArtifact):
        store.get("never-issued")


def test_discard_expired_removes_only_stale_entries():
    clock = FakeClock()
    store = ArtifactStore(ttl=10, clock=clock)
    fresh = make_artifact(store, clock)
    stale = make_artifact(store, clock)
    store.get(stale).expires_at = clock() - 1

    assert store.discard_expired() == 1
    assert stale not in store
    assert fresh in store
    with pytest.raises(UnknownArtifact):
        store.get(stale)


def test_backward_compatible_dict_access_returns_message():
    clock = FakeClock()
    store = ArtifactStore(ttl=10, clock=clock)
    artifact = make_artifact(store, clock)
    assert store[artifact] == "message"
    assert len(store) == 1
