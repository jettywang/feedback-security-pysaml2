"""Security contract tests for the SAML 2.0 HTTP Artifact binding.

The scenarios run entirely in process: an in-memory transport replaces the
SOAP back channel so no network port is needed. Two local service providers
(SP1 and SP2, each with its own key pair) talk to one identity provider.

Covered contracts:

* one artifact is bound to exactly one recipient, its SourceID and endpoint
  index;
* a signed ArtifactResolve is mandatory before anything is released;
* the wrong SP can never consume another SP's artifact, not even by reusing
  the reference over an alternative transport;
* a lost successful ArtifactResponse can be retried by the legitimate SP
  with an identical result, while the reference never becomes a general
  assertion download;
* expired and unknown artifacts return the same outside error while the
  store keeps the two causes distinguishable internally;
* the normal single exchange still works end to end.
"""

from contextlib import closing
from hashlib import sha1

import pytest

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_SOAP
from saml2 import extension_elements_to_elements
from saml2 import saml
from saml2 import samlp
from saml2.artifact import ArtifactResolutionDenied
from saml2.artifact import ExpiredArtifact
from saml2.artifact import InvalidArtifact
from saml2.artifact import UnknownArtifact
from saml2.artifact import decode_artifact
from saml2.client import Saml2Client
from saml2.response import IncorrectlySigned
from saml2.samlp import STATUS_REQUEST_DENIED
from saml2.samlp import STATUS_REQUESTER
from saml2.samlp import STATUS_SUCCESS
from saml2.server import Server
from saml2.s_utils import sid


IDP_CONF = "artifact_idp_conf"
SP1_CONF = "artifact_sp1_conf"
SP2_CONF = "artifact_sp2_conf"


def ars_of(entity):
    """The artifact resolution service URL of the entity itself."""
    return entity.config.endpoint("artifact_resolution_service", BINDING_SOAP, entity.entity_type)[0]


def peer_ars(metadata, peer_entity_id, descriptor):
    """Artifact resolution service URL of a remote entity from metadata."""
    return metadata.artifact_resolution_service(peer_entity_id, BINDING_SOAP, descriptor)[0]["location"]


class InMemoryTransport:
    """SOAP stand-in that hands the envelope straight to the receiver.

    ``deliver`` mimics one back-channel call. The optional ``intercept`` lets
    a test substitute what the receiver actually gets (for example an
    unsigned envelope) without touching the sender's state, which is how the
    alternative transport attacks are modelled.
    """

    def __init__(self):
        self.calls = []

    def deliver(self, sender, receiver, message, intercept=None):
        self.calls.append((sender.config.entityid, receiver.config.entityid))
        payload = intercept if intercept is not None else message
        return receiver.handle_artifact_resolve(payload)



def status_value(response):
    """Return the meaningful SAML status code.

    Error responses carry a top level Requester/Responder code with the
    specific reason in the nested second level code.
    """
    top = response.status.status_code
    if top.status_code is not None:
        return top.status_code.value
    return top.value


@pytest.fixture
def topology():
    sp1 = Saml2Client(config_file=SP1_CONF)
    sp2 = Saml2Client(config_file=SP2_CONF)
    with closing(Server(config_file=IDP_CONF)) as idp:
        yield {"sp1": sp1, "sp2": sp2, "idp": idp, "transport": InMemoryTransport()}


def signed_resolve_soap(requester, artifact, destination):
    """Build a signed, SOAP enveloped ArtifactResolve as the requester."""
    _msg_id, msg = requester.create_artifact_resolve(artifact, destination, sid(), sign=True)
    return requester.use_soap(msg, destination, None, False)["data"]


def unsigned_resolve_soap(requester, artifact, destination):
    """Build an unsigned ArtifactResolve to simulate a bad requester."""
    _msg_id, msg = requester.create_artifact_resolve(artifact, destination, sid(), sign=False)
    return requester.use_soap(msg, destination, None, False)["data"]


def idp_artifact(idp, sp):
    """Mint an IdP artifact bound to a given SP and return (artifact, record)."""
    _msg_id, authn_response = idp.create_artifact_resolve("placeholder", ars_of(idp), sid())
    artifact = idp.use_artifact(authn_response, 1, recipient_entity_id=sp.config.entityid)
    return artifact, idp.artifact.get(artifact)


def test_artifact_is_bound_to_recipient_sourceid_and_index(topology):
    idp = topology["idp"]
    sp1 = topology["sp1"]

    artifact, record = idp_artifact(idp, sp1)

    typecode, endpoint_index, source_id, _handle = decode_artifact(artifact)

    assert record.recipient_entity_id == sp1.config.entityid
    assert record.endpoint_index == endpoint_index == 1
    assert record.source_id == source_id == sha1(idp.config.entityid.encode("utf-8")).digest()
    assert typecode == b"\x00\x04"

    info = idp.artifact_info(artifact)
    assert info["endpoint_index"] == 1
    assert info["source_id"] == source_id

    # The SourceID routes back to the IdP's own artifact resolution service.
    destination = sp1.artifact2destination(artifact, "idpsso")
    assert destination == ars_of(idp)


def test_malformed_artifact_is_rejected(topology):
    sp1 = topology["sp1"]
    with pytest.raises(InvalidArtifact):
        sp1.artifact_info("not-an-artifact")
    with pytest.raises(InvalidArtifact):
        sp1.artifact2destination("AAAAAAAAAAAAAAAAAAAAAA==", "idpsso")


def test_unsigned_resolve_cannot_touch_artifact(topology):
    idp = topology["idp"]
    sp1 = topology["sp1"]

    artifact, record = idp_artifact(idp, sp1)
    soap = unsigned_resolve_soap(sp1, artifact, ars_of(idp))

    with pytest.raises(IncorrectlySigned):
        idp.parse_artifact_resolve(soap)

    # The failed authentication must not consume or alter the artifact.
    assert record.resolved_count == 0
    assert idp.artifact.get(artifact) is record


def test_wrong_sp_cannot_resolve_artifact(topology):
    idp = topology["idp"]
    sp1 = topology["sp1"]
    sp2 = topology["sp2"]
    transport = topology["transport"]

    artifact, record = idp_artifact(idp, sp1)
    soap = signed_resolve_soap(sp2, artifact, ars_of(idp))

    response = transport.deliver(sp2, idp, soap)

    # No assertion leaves the IdP: an error status comes back instead.
    assert status_value(response) == STATUS_REQUEST_DENIED
    assert not response.extension_elements
    assert record.resolved_count == 0

    # Direct store access confirms the binding is enforced centrally.
    with pytest.raises(ArtifactResolutionDenied):
        idp.artifact.resolve(artifact, sp2.config.entityid)
    assert idp.artifact.resolve(artifact, sp1.config.entityid) == record.message


def test_alternative_transport_cannot_launder_artifact(topology):
    """SP2 re-signs SP1's reference and sends it over its own SOAP channel."""
    idp = topology["idp"]
    sp1 = topology["sp1"]
    sp2 = topology["sp2"]
    transport = topology["transport"]

    artifact, record = idp_artifact(idp, sp1)

    # SP2 obtained the short reference (e.g. from a redirected browser) and
    # presents it with its own valid signature.
    sp2_soap = signed_resolve_soap(sp2, artifact, ars_of(idp))
    response = transport.deliver(sp2, idp, sp2_soap)

    assert status_value(response) == STATUS_REQUEST_DENIED
    assert record.resolved_count == 0

    # A tampered, unsigned envelope on the same channel is rejected outright.
    tampered = unsigned_resolve_soap(sp2, artifact, ars_of(idp))
    with pytest.raises(IncorrectlySigned):
        transport.deliver(sp2, idp, tampered)
    assert record.resolved_count == 0


def test_legitimate_single_exchange_and_retry_after_lost_response(topology):
    idp = topology["idp"]
    sp1 = topology["sp1"]
    sp2 = topology["sp2"]
    transport = topology["transport"]

    artifact, record = idp_artifact(idp, sp1)

    first_soap = signed_resolve_soap(sp1, artifact, ars_of(idp))
    first_response = transport.deliver(sp1, idp, first_soap)

    assert first_response.status.status_code.value == STATUS_SUCCESS
    assert record.resolved_count == 1

    # Simulate the response being lost before the SP could store it: the SP
    # retries the exact same reference. The same message is returned again
    # rather than an error, and never becomes downloadable by anyone else.
    second_soap = signed_resolve_soap(sp1, artifact, ars_of(idp))
    second_response = transport.deliver(sp1, idp, second_soap)

    assert second_response.status.status_code.value == STATUS_SUCCESS
    assert record.resolved_count == 2
    # The retried response must carry the exact same stored message.
    def embedded(response):
        elements = extension_elements_to_elements(response.extension_elements, [samlp, saml])
        return f"{elements[0]}"

    expected = f"{idp.artifact[artifact]}"
    assert embedded(first_response) == expected
    assert embedded(second_response) == expected

    # SP2 still cannot piggyback on the now repeatedly resolved artifact.
    sp2_soap = signed_resolve_soap(sp2, artifact, ars_of(idp))
    denied = transport.deliver(sp2, idp, sp2_soap)
    assert status_value(denied) == STATUS_REQUEST_DENIED


def test_expired_and_unknown_are_identical_outside_distinct_inside(topology):
    idp = topology["idp"]
    sp1 = topology["sp1"]
    transport = topology["transport"]

    artifact, record = idp_artifact(idp, sp1)

    # Force expiry in place instead of waiting for the TTL.
    record.expires_at = record.issued_at - 1

    # Internally the store knows the difference.
    with pytest.raises(ExpiredArtifact):
        idp.artifact.get(artifact)
    with pytest.raises(UnknownArtifact):
        idp.artifact.get("AAAA" + artifact[4:])

    expired_soap = signed_resolve_soap(sp1, artifact, ars_of(idp))
    expired_response = transport.deliver(sp1, idp, expired_soap)

    unknown_soap = signed_resolve_soap(sp1, "AAAA" + artifact[4:], ars_of(idp))
    unknown_response = transport.deliver(sp1, idp, unknown_soap)

    # Externally both failures use the same generic Requester status and
    # carry no message, so existence cannot be probed.
    assert status_value(expired_response) == STATUS_REQUESTER
    assert status_value(unknown_response) == STATUS_REQUESTER
    assert not expired_response.extension_elements
    assert not unknown_response.extension_elements
    assert record.resolved_count == 0


def test_sp_side_artifact_is_also_bound_to_idp(topology):
    sp1 = topology["sp1"]
    sp2 = topology["sp2"]
    idp = topology["idp"]

    sso = sp1.metadata.single_sign_on_service(idp.config.entityid, BINDING_HTTP_REDIRECT)[0]["location"]
    _req_id, authn_request = sp1.create_authn_request(sso)
    artifact = sp1.use_artifact(authn_request, 1, recipient_entity_id=idp.config.entityid)
    record = sp1.artifact.get(artifact)

    assert record.recipient_entity_id == idp.config.entityid
    with pytest.raises(ArtifactResolutionDenied):
        sp1.artifact.resolve(artifact, sp2.config.entityid)

    # The IdP routes the artifact to SP1's resolution service.
    destination = idp.artifact2destination(artifact, "spsso")
    assert destination == peer_ars(idp.metadata, sp1.config.entityid, "spsso")
