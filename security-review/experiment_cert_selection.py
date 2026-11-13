#!/usr/bin/env python3
"""Offline experiment: KeyDescriptor selection boundaries in pysaml2 7.5.5.

The script never touches the network. It generates its own RSA key pairs and
self-signed certificates with the `cryptography` package, builds a single
EntityDescriptor containing IDPSSODescriptor, SPSSODescriptor and
AttributeAuthorityDescriptor, loads it through the real pysaml2 metadata
stack (InMemoryMetaData -> MetaData.certs) and finally exercises the real
signature verification path (SecurityContext._check_signature via xmlsec1).

Run:
    .venv/bin/python security-review/experiment_cert_selection.py
Optional env:
    XMLSEC1=/path/to/xmlsec1   (otherwise PATH is searched)
"""
import datetime
import hashlib
import os
import sys
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from saml2.attribute_converter import ac_factory
from saml2.mdstore import InMemoryMetaData

ENTITY_ID = "urn:example:multi-role-entity"
MD = "urn:oasis:names:tc:SAML:2.0:metadata"
DS = "http://www.w3.org/2000/09/xmldsig#"


def make_key_cert(cn, days_valid=3650, not_before_offset_days=0):
    """Return (private_key PEM bytes, cert PEM bytes, base64 DER str)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=not_before_offset_days))
        .not_valid_after(now + datetime.timedelta(days=days_valid))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    b64 = "".join(cert_pem.decode().splitlines()[1:-1])
    return key_pem, cert_pem, b64


def fp(b64_der):
    """SHA-256 fingerprint of the DER certificate, short label."""
    return hashlib.sha256(b64_der.encode()).hexdigest()[:16]


def kd(use, b64):
    use_attr = f' use="{use}"' if use else ""
    return (
        f"<KeyDescriptor{use_attr}><ds:KeyInfo><ds:X509Data>"
        f"<ds:X509Certificate>{b64}</ds:X509Certificate>"
        f"</ds:X509Data></ds:KeyInfo></KeyDescriptor>"
    )


def build_metadata(role_kds):
    """role_kds: dict role -> list of KeyDescriptor XML strings."""
    def role_tag(role):
        return {
            "idpsso": "IDPSSODescriptor",
            "spsso": "SPSSODescriptor",
            "attribute_authority": "AttributeAuthorityDescriptor",
        }[role]

    parts = [
        f'<EntityDescriptor xmlns="{MD}" xmlns:ds="{DS}" entityID="{ENTITY_ID}">'
    ]
    for role, kds_list in role_kds.items():
        tag = role_tag(role)
        extra = ' WantAuthnRequestsSigned="false"' if role == "spsso" else ""
        parts.append(
            f'<{tag}{extra} protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            + "".join(kds_list)
            + f"</{tag}>"
        )
    parts.append("</EntityDescriptor>")
    return "".join(parts)


def load(md_xml):
    import saml2
    attrc = ac_factory(os.path.join(os.path.dirname(saml2.__file__), "attributemaps"))
    md = InMemoryMetaData(attrc, md_xml)
    md.load()
    return md


def labels(selection):
    return [(name, fp(cert.replace("\n", ""))) for name, cert in selection]


RESULTS = []


def record(case_id, title, verdict, detail):
    RESULTS.append((case_id, verdict, title, detail))
    mark = {"PROBLEM": "PROBLEM", "SAFE": "SAFE", "NOTE": "NOTE"}[verdict]
    print(f"[{mark}] {case_id} {title}\n        {detail}")


def assert_eq(case_id, title, got, expected):
    verdict = "SAFE" if got == expected else "PROBLEM"
    record(case_id, title, verdict, f"expected={expected} got={got}")
    return got == expected


def main():
    # ------------------------------------------------------------------ keys
    keys = {}
    for name in ["idp_sign", "idp_enc", "sp_sign", "sp_enc", "aa_sign", "shared", "rot_old", "rot_new"]:
        keys[name] = make_key_cert(f"cn-{name}")
    b64 = {name: t[2] for name, t in keys.items()}
    fps = {name: fp(t[2]) for name, t in keys.items()}
    print("Generated certificates (sha256 prefix):")
    for name, f in fps.items():
        print(f"  {name:9s} {f}")
    print()

    # ------------------------- Scenario 1: role + use selection boundaries
    role_kds = {
        "idpsso": [kd("signing", b64["idp_sign"]), kd("encryption", b64["idp_enc"])],
        "spsso": [kd("signing", b64["sp_sign"]), kd("encryption", b64["sp_enc"])],
        "attribute_authority": [kd("signing", b64["aa_sign"])],
    }
    md = load(build_metadata(role_kds))

    sel_idp_sign = labels(md.certs(ENTITY_ID, "idpsso", "signing"))
    assert_eq("S1a", "idpsso/signing returns only the IdP signing cert",
              [f for _, f in sel_idp_sign], [fps["idp_sign"]])
    sel_idp_enc = labels(md.certs(ENTITY_ID, "idpsso", "encryption"))
    assert_eq("S1b", "idpsso/encryption returns only the IdP encryption cert",
              [f for _, f in sel_idp_enc], [fps["idp_enc"]])
    sel_sp = labels(md.certs(ENTITY_ID, "spsso", "signing"))
    assert_eq("S1c", "spsso/signing is role-scoped when descriptor is explicit",
              [f for _, f in sel_sp], [fps["sp_sign"]])

    any_sign = labels(md.certs(ENTITY_ID, "any", "signing"))
    any_sign_fps = [f for _, f in any_sign]
    record(
        "S1d",
        "all production callers use descriptor='any': signing pool spans IdP+SP+AA roles",
        "PROBLEM" if set(any_sign_fps) == {fps["idp_sign"], fps["sp_sign"], fps["aa_sign"]} else "NOTE",
        f"any/signing pool = {any_sign_fps}",
    )
    any_enc = labels(md.certs(ENTITY_ID, "any", "encryption"))
    record(
        "S1e",
        "any/encryption pool spans every role descriptor as well",
        "PROBLEM" if {f for _, f in any_enc} == {fps["idp_enc"], fps["sp_enc"]} else "NOTE",
        f"any/encryption pool = {[f for _, f in any_enc]}",
    )

    # ------------------------- Scenario 2: unspecified use matches both
    role_kds2 = {
        "idpsso": [kd(None, b64["shared"])],
        "spsso": [kd("signing", b64["sp_sign"])],
        "attribute_authority": [],
    }
    md2 = load(build_metadata(role_kds2))
    unspec_sign = [f for _, f in labels(md2.certs(ENTITY_ID, "idpsso", "signing"))]
    unspec_enc = [f for _, f in labels(md2.certs(ENTITY_ID, "idpsso", "encryption"))]
    assert_eq("S2a", "KeyDescriptor without use is selected for signing", unspec_sign, [fps["shared"]])
    assert_eq("S2b", "KeyDescriptor without use is selected for encryption", unspec_enc, [fps["shared"]])

    # ------------------------- Scenario 3: same fingerprint repeated
    role_kds3 = {
        "idpsso": [kd("signing", b64["shared"]), kd("signing", b64["shared"])],
        "spsso": [kd("signing", b64["shared"])],
        "attribute_authority": [kd("signing", b64["shared"])],
    }
    md3 = load(build_metadata(role_kds3))
    raw = md3.certs(ENTITY_ID, "any", "signing")
    fps3 = [f for _, f in labels(raw)]
    dup_within = len(md3.certs(ENTITY_ID, "idpsso", "signing"))
    record(
        "S3a",
        "dedupe check compares PEM text to (key_name, cert) tuples and never matches",
        "PROBLEM" if dup_within == 2 else "NOTE",
        f"idpsso signing entries for one duplicated cert = {dup_within}",
    )
    record(
        "S3b",
        "same cert repeated across roles yields 4 entries in the any-pool",
        "PROBLEM" if len(fps3) == 4 and len(set(fps3)) == 1 else "NOTE",
        f"any/signing entries = {len(fps3)}, distinct fingerprints = {len(set(fps3))}",
    )

    # ------------------------- Scenario 4: rotation overlap (two valid certs)
    role_kds4 = {"idpsso": [kd("signing", b64["rot_old"]), kd("signing", b64["rot_new"])]}
    md4 = load(build_metadata(role_kds4))
    rot = [f for _, f in labels(md4.certs(ENTITY_ID, "idpsso", "signing"))]
    assert_eq("S4", "rotation overlap: both old and new signing certs are retained, in metadata order",
              rot, [fps["rot_old"], fps["rot_new"]])

    # ------------------------- Scenario 5: expired cert is not filtered
    _, _, expired_b64 = make_key_cert("cn-expired", days_valid=1, not_before_offset_days=-30)
    role_kds5 = {"idpsso": [kd("signing", expired_b64), kd("signing", b64["rot_new"])]}
    md5 = load(build_metadata(role_kds5))
    exp_selection = md5.certs(ENTITY_ID, "any", "signing")
    record(
        "S5",
        "metadata cert selection performs no notBefore/notAfter filtering",
        "PROBLEM" if len(exp_selection) == 2 else "NOTE",
        f"signing pool size with one expired cert present = {len(exp_selection)}",
    )

    # ------------------------- Scenario 6: end-to-end cross-role verification
    e2e_cross_role(keys, b64, fps)

    # ------------------------- Scenario 8: encryption-only cert cannot verify
    e2e_encryption_only_rejected(keys, b64, fps)

    # ------------------------- Scenario 9: KeyInfo without X509Data
    scenario_keyname_only(b64, fps)

    # ------------------------- Scenario 7: unsigned metadata is accepted
    record(
        "S7",
        "parse_and_check_signature returns True when no metadata-signing cert is configured",
        "NOTE",
        "see mdstore.py:731-735; trust in every KeyDescriptor then depends on the deployment channel",
    )

    print("\n================ SUMMARY ================")
    problems = [r for r in RESULTS if r[1] == "PROBLEM"]
    safes = [r for r in RESULTS if r[1] == "SAFE"]
    notes = [r for r in RESULTS if r[1] == "NOTE"]
    print(f"SAFE={len(safes)} PROBLEM={len(problems)} NOTE={len(notes)}")
    return 1 if problems else 0


def e2e_cross_role(keys, b64, fps):
    """Sign a Response with the AA role's key; verify via metadata any-pool."""
    import tempfile
    from saml2 import saml, samlp, class_name, sigver
    from saml2.s_utils import factory, success_status_factory
    from saml2.sigver import get_xmlsec_binary, CryptoBackendXmlSec1, SecurityContext

    aa_key_pem, aa_cert_pem, aa_b64 = keys["aa_sign"]
    sp_sign_b64 = b64["sp_sign"]
    idp_sign_b64 = b64["idp_sign"]

    tmpdir = tempfile.mkdtemp(prefix="pysaml2-exp-")
    aa_key_file = os.path.join(tmpdir, "aa.key")
    aa_cert_file = os.path.join(tmpdir, "aa.crt")
    with open(aa_key_file, "wb") as f:
        f.write(aa_key_pem)
    with open(aa_cert_file, "wb") as f:
        f.write(aa_cert_pem)

    role_kds = {
        "idpsso": [kd("signing", idp_sign_b64)],
        "spsso": [kd("signing", sp_sign_b64)],
        "attribute_authority": [kd("signing", aa_b64)],
    }
    md = load(build_metadata(role_kds))

    xmlsec = os.environ.get("XMLSEC1") or get_xmlsec_binary()
    crypto = CryptoBackendXmlSec1(xmlsec)

    sec = SecurityContext(
        crypto,
        aa_key_file,
        cert_file=aa_cert_file,
        metadata=md,
        only_use_keys_in_metadata=True,
        validate_certificate=False,
        delete_tmpfiles=True,
    )

    assertion = factory(
        saml.Assertion,
        version="2.0",
        id="id-exp-%s" % uuid.uuid4().hex[:8],
        issuer=saml.Issuer(text=ENTITY_ID),
        issue_instant="2099-01-01T00:00:00Z",
    )
    response = factory(
        samlp.Response,
        issuer=saml.Issuer(text=ENTITY_ID),
        status=success_status_factory(),
        assertion=assertion,
        version="2.0",
        issue_instant="2099-01-01T00:00:00Z",
        id="id-resp-%s" % uuid.uuid4().hex[:8],
    )
    assertion.signature = sigver.pre_signature_part(
        assertion.id, "".join(aa_cert_pem.decode().splitlines()[1:-1]), 1
    )
    response.signature = sigver.pre_signature_part(
        response.id, "".join(aa_cert_pem.decode().splitlines()[1:-1])
    )
    to_sign = [(class_name(assertion), assertion.id), (class_name(response), response.id)]
    signed_xml = sigver.signed_instance_factory(response, sec, to_sign)
    parsed = samlp.response_from_string(signed_xml)

    pool = [f for _, f in labels(md.certs(ENTITY_ID, "any", "signing"))]
    try:
        sec._check_signature(signed_xml, parsed, class_name(parsed), signed_xml)
        outcome = True
        err = ""
    except Exception as exc:  # noqa: BLE001
        outcome = False
        err = f"{type(exc).__name__}: {exc}"
    record(
        "S6",
        "message signed with the AttributeAuthority key verifies through the role-agnostic any-pool",
        "PROBLEM" if outcome else "NOTE",
        f"verified={outcome}; pool={pool}{'; ' + err if err else ''}",
    )

    # Negative control: sign with a key that appears nowhere in metadata.
    foreign_key, foreign_cert, foreign_b64 = make_key_cert("cn-foreign")
    fk_file = os.path.join(tmpdir, "foreign.key")
    fc_file = os.path.join(tmpdir, "foreign.crt")
    open(fk_file, "wb").write(foreign_key)
    open(fc_file, "wb").write(foreign_cert)
    sec2 = SecurityContext(
        crypto,
        fk_file,
        cert_file=fc_file,
        metadata=md,
        only_use_keys_in_metadata=True,
        validate_certificate=False,
        delete_tmpfiles=True,
    )
    assertion2 = factory(
        saml.Assertion,
        version="2.0",
        id="id-exp2-%s" % uuid.uuid4().hex[:8],
        issuer=saml.Issuer(text=ENTITY_ID),
        issue_instant="2099-01-01T00:00:00Z",
    )
    response2 = factory(
        samlp.Response,
        issuer=saml.Issuer(text=ENTITY_ID),
        status=success_status_factory(),
        assertion=assertion2,
        version="2.0",
        issue_instant="2099-01-01T00:00:00Z",
        id="id-resp2-%s" % uuid.uuid4().hex[:8],
    )
    assertion2.signature = sigver.pre_signature_part(
        assertion2.id, "".join(foreign_cert.decode().splitlines()[1:-1]), 1
    )
    response2.signature = sigver.pre_signature_part(
        response2.id, "".join(foreign_cert.decode().splitlines()[1:-1])
    )
    signed2 = sigver.signed_instance_factory(response2, sec2,
                                             [(class_name(assertion2), assertion2.id),
                                              (class_name(response2), response2.id)])
    parsed2 = samlp.response_from_string(signed2)
    try:
        sec._check_signature(signed2, parsed2, class_name(parsed2), signed2)
        rejected = False
    except Exception:  # noqa: BLE001
        rejected = True
    record(
        "S6-neg",
        "key absent from every role descriptor is rejected (only_use_keys_in_metadata=True)",
        "SAFE" if rejected else "PROBLEM",
        f"rejected={rejected}",
    )


def e2e_encryption_only_rejected(keys, b64, fps):
    """A message signed with an encryption-only role key must not verify."""
    import tempfile
    from saml2 import saml, samlp, class_name, sigver
    from saml2.s_utils import factory, success_status_factory
    from saml2.sigver import get_xmlsec_binary, CryptoBackendXmlSec1, SecurityContext

    enc_key_pem, enc_cert_pem, enc_b64 = keys["idp_enc"]
    tmpdir = tempfile.mkdtemp(prefix="pysaml2-exp-enc-")
    kf = os.path.join(tmpdir, "enc.key")
    cf = os.path.join(tmpdir, "enc.crt")
    open(kf, "wb").write(enc_key_pem)
    open(cf, "wb").write(enc_cert_pem)

    md = load(build_metadata({"idpsso": [kd("encryption", enc_b64)], "spsso": [], "attribute_authority": []}))
    crypto = CryptoBackendXmlSec1(os.environ.get("XMLSEC1") or get_xmlsec_binary())
    sec = SecurityContext(
        crypto, kf, cert_file=cf, metadata=md,
        only_use_keys_in_metadata=True, validate_certificate=False, delete_tmpfiles=True,
    )
    signing_pool = md.certs(ENTITY_ID, "any", "signing")
    assertion = factory(
        saml.Assertion, version="2.0", id="id-en-%s" % uuid.uuid4().hex[:8],
        issuer=saml.Issuer(text=ENTITY_ID), issue_instant="2099-01-01T00:00:00Z",
    )
    response = factory(
        samlp.Response, issuer=saml.Issuer(text=ENTITY_ID), status=success_status_factory(),
        assertion=assertion, version="2.0", issue_instant="2099-01-01T00:00:00Z",
        id="id-enr-%s" % uuid.uuid4().hex[:8],
    )
    cert_b64 = "".join(enc_cert_pem.decode().splitlines()[1:-1])
    assertion.signature = sigver.pre_signature_part(assertion.id, cert_b64, 1)
    response.signature = sigver.pre_signature_part(response.id, cert_b64)
    signed = sigver.signed_instance_factory(
        response, sec, [(class_name(assertion), assertion.id), (class_name(response), response.id)]
    )
    parsed = samlp.response_from_string(signed)
    try:
        sec._check_signature(signed, parsed, class_name(parsed), signed)
        rejected = False
        detail = "encryption-only key verified a signature"
    except sigver.MissingKey:
        rejected = True
        detail = "signing pool empty -> MissingKey before any xmlsec1 attempt"
    except Exception as exc:  # noqa: BLE001
        rejected = True
        detail = f"rejected with {type(exc).__name__}"
    record(
        "S8",
        "encryption-only KeyDescriptor is excluded from the signing verification path",
        "SAFE" if rejected and not signing_pool else "PROBLEM",
        f"rejected={rejected}; any/signing pool size={len(signing_pool)}; {detail}",
    )


def scenario_keyname_only(b64, fps):
    """A KeyName-only KeyDescriptor aborts cert enumeration for the entity."""
    bad_kd = (
        '<KeyDescriptor use="signing"><ds:KeyInfo><ds:KeyName>only-a-name</ds:KeyName>'
        "</ds:KeyInfo></KeyDescriptor>"
    )
    good_kd = kd("signing", b64["rot_new"])
    md = load(build_metadata({"idpsso": [bad_kd, good_kd], "spsso": [], "attribute_authority": []}))
    try:
        selection = md.certs(ENTITY_ID, "any", "signing")
    except KeyError as exc:
        record(
            "S9",
            "KeyDescriptor without X509Data aborts certs() and hides later valid certs",
            "PROBLEM",
            f"KeyError({exc!r}); the second, valid KeyDescriptor is never reached",
        )
        return
    record("S9", "unexpectedly tolerated KeyInfo without X509Data", "NOTE", f"selection={selection}")


if __name__ == "__main__":
    sys.exit(main())
