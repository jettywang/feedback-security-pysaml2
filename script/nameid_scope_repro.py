#!/usr/bin/env python
"""Local NameID scope reproduction for pysaml2 7.5.5.

Run from the repository root:

    .venv/bin/python script/nameid_scope_repro.py

The script does not change pysaml2 behaviour.  It prints the concrete keys
used by IdentDB, SessionStorage and Server.gather_authn_response_args.
"""
import os
import sys
from hashlib import sha1

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "tests"))

from pathutils import full_path
from saml2.authn_context import INTERNETPROTOCOLPASSWORD
from saml2.config import IdPConfig
from saml2.ident import IdentDB
from saml2.ident import code
from saml2.ident import code_binary
from saml2.ident import decode
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from saml2.saml import NAMEID_FORMAT_PERSISTENT
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NameID
from saml2.samlp import NameIDPolicy
from saml2.samlp import name_id_policy_from_string
from saml2.s_utils import PolicyError
from saml2.sdb import SessionStorage
from saml2.server import Server


IDP = "https://idp.example.org"
SP_A = "urn:mace:example.com:saml:roland:sp"
SP_B = "https://example.com/sp"
TEXT = "shared-user-text"
AVA = {"givenName": ["Alice"], "sn": ["A"], "mail": ["alice@example.org"]}
AUTHN = {"class_ref": INTERNETPROTOCOLPASSWORD, "authn_auth": f"{IDP}/login"}


def show(label, value):
    print(f"  {label}: {value}")


def section(title):
    print(f"\n== {title} ==")


def local_identdb():
    """Same text with different NameQualifier/SPNameQualifier/Format."""
    section("IdentDB forward/reverse keys (text-only reverse index)")
    db = IdentDB({}, domain="example.org", name_qualifier=IDP)
    name_a = NameID(
        format=NAMEID_FORMAT_PERSISTENT,
        text=TEXT,
        sp_name_qualifier=SP_A,
        name_qualifier=IDP,
    )
    name_b = NameID(
        format=NAMEID_FORMAT_PERSISTENT,
        text=TEXT,
        sp_name_qualifier=SP_B,
        name_qualifier=IDP,
    )

    db.store("user-A", name_a)
    db.store("user-B", name_b)
    show("forward key user-A", db.db["user-A"])
    show("forward key user-B", db.db["user-B"])
    show("reverse key is exactly NameID.text", repr(TEXT))
    show("find_local_id(A) ->", db.find_local_id(name_a))
    show("find_local_id(B) ->", db.find_local_id(name_b))
    show("name_a.code", code(name_a))
    show("name_b.code", code(name_b))

    try:
        db.remove_remote(name_a)
        print("  remove_remote(A) unexpectedly succeeded")
    except ValueError as exc:
        show("remove_remote(A) ValueError", exc)
    show("after remove_remote, reverse(A) ->", db.find_local_id(name_a))
    show("after remove_remote, reverse(B) ->", db.find_local_id(name_b))

    section("match_local_id ignores Format but checks both qualifiers")
    db2 = IdentDB({}, domain="example.org", name_qualifier=IDP)
    email = db2.get_nameid("alice", NAMEID_FORMAT_EMAILADDRESS, SP_A, IDP)
    show("email issued", (email.format, email.text))
    persistent = db2.persistent_nameid("alice", SP_A, IDP)
    show("persistent_nameid returned", (persistent.format, persistent.text))
    show("same text?", persistent.text == email.text)
    show("forward record", db2.db["alice"])

    section("same text and qualifiers, different Format, one user")
    db3 = IdentDB({}, domain="example.org", name_qualifier=IDP)
    fmt_a = NameID(format=NAMEID_FORMAT_PERSISTENT, text=TEXT, sp_name_qualifier=SP_A, name_qualifier=IDP)
    fmt_b = NameID(format=NAMEID_FORMAT_EMAILADDRESS, text=TEXT, sp_name_qualifier=SP_A, name_qualifier=IDP)
    db3.store("user-A", fmt_a)
    db3.store("user-A", fmt_b)
    show("reverse lookup is text-only", db3.find_local_id(fmt_a))
    show("forward record", db3.db["user-A"])


def server_config():
    return {
        "entityid": IDP,
        "service": {
            "idp": {
                "endpoints": {
                    "single_sign_on_service": [(f"{IDP}/sso", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")],
                    "single_logout_service": [(f"{IDP}/slo", "urn:oasis:names:tc:SAML:2.0:bindings:SOAP")],
                    "name_id_mapping_service": [(f"{IDP}/nim", "urn:oasis:names:tc:SAML:2.0:bindings:SOAP")],
                },
                "policy": {
                    "default": {
                        "lifetime": {"minutes": 5},
                        "attribute_restrictions": None,
                        "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
                        "nameid_format": NAMEID_FORMAT_PERSISTENT,
                    }
                },
                "subject_data": ("dict", ""),
            }
        },
        "key_file": full_path("test.key"),
        "cert_file": full_path("test.pem"),
        "metadata": [
            {
                "class": "saml2.mdstore.MetaDataFile",
                "metadata": [(full_path("metadata_sp_1.xml"),), (full_path("metadata_sp_2.xml"),)],
            }
        ],
        "attribute_map_dir": full_path("attributemaps"),
    }


def issue(idp, sp, policy, userid, tag):
    response = idp.create_authn_response(
        AVA,
        f"req-{tag}",
        "https://sp.example.org/acs",
        sp,
        name_id_policy=policy,
        userid=userid,
        authn=AUTHN,
    )
    return response.assertion.subject.name_id


def server_first_issue_and_allow_create():
    section("First issue through Server.gather_authn_response_args")
    idp = Server(config=IdPConfig().load(server_config()))
    policy_a = NameIDPolicy(format=NAMEID_FORMAT_PERSISTENT, allow_create="false")
    policy_b = NameIDPolicy(
        format=NAMEID_FORMAT_PERSISTENT,
        allow_create="false",
        sp_name_qualifier=SP_B,
    )
    a = issue(idp, SP_A, policy_a, "alice", "A")
    b = issue(idp, SP_B, policy_b, "alice", "B")
    show("SP-A NameID", (a.format, a.text, a.sp_name_qualifier, a.name_qualifier))
    show("SP-B NameID", (b.format, b.text, b.sp_name_qualifier, b.name_qualifier))
    show("same text across SPs?", a.text == b.text)
    show("ident forward keys", sorted(idp.ident.db.keys()))
    show("find_nameid(userid=alice, sp_name_qualifier=SP_A)", idp.ident.find_nameid("alice", sp_name_qualifier=SP_A))
    show("find_nameid(userid=alice, sp_name_qualifier=SP_B)", idp.ident.find_nameid("alice", sp_name_qualifier=SP_B))

    section("SP-A sends SPNameQualifier=SP-B (request field controls scope)")
    c = issue(idp, SP_A, policy_b, "alice", "A-asking-B")
    show("returned text equals SP-B's", c.text == b.text)
    show("returned SNQ", c.sp_name_qualifier)
    show("reverse lookup still text-only", idp.ident.find_local_id(c))

    section("SSO does not enforce AllowCreate=false")
    fresh = Server(config=IdPConfig().load(server_config()))
    policy_c = NameIDPolicy(format=NAMEID_FORMAT_PERSISTENT, allow_create="false")
    c2 = issue(fresh, SP_B, policy_c, "alice", "new-sp")
    show("SP-B's first login with AllowCreate=false still got", (c2.format, c2.text))
    fresh.close()
    idp.close()


def policy_helpers():
    section("NameIDMapping: AllowCreate is only compared to literal string 'false'")
    qualified = NameID(
        format=NAMEID_FORMAT_PERSISTENT,
        text=TEXT,
        sp_name_qualifier=SP_A,
        name_qualifier=IDP,
    )
    for label, policy_xml in [
        ("AllowCreate=false", '<NameIDPolicy xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Format="%s" AllowCreate="false"/>' % NAMEID_FORMAT_PERSISTENT),
        ("AllowCreate=0", '<NameIDPolicy xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Format="%s" AllowCreate="0"/>' % NAMEID_FORMAT_PERSISTENT),
        ("no AllowCreate", '<NameIDPolicy xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Format="%s"/>' % NAMEID_FORMAT_PERSISTENT),
    ]:
        db = IdentDB({}, name_qualifier=IDP)
        db.store("user-A", qualified)
        policy = name_id_policy_from_string(policy_xml)
        try:
            result = db.handle_name_id_mapping_request(qualified, policy)
            show(f"{label}: created", (result.format, result.text, result.sp_name_qualifier))
        except PolicyError as exc:
            show(f"{label}: PolicyError", exc)

    section("NameIDMapping returns an unqualified durable ID shared by both SPs")
    db = IdentDB({}, name_qualifier=IDP)
    id_a = NameID(format=NAMEID_FORMAT_PERSISTENT, text="id-for-A", sp_name_qualifier=SP_A, name_qualifier=IDP)
    id_b = NameID(format=NAMEID_FORMAT_PERSISTENT, text="id-for-B", sp_name_qualifier=SP_B, name_qualifier=IDP)
    # one local user, two SP-scoped NameIDs, as Server.gather_authn_response_args produces
    db.store("alice", id_a)
    db.store("alice", id_b)
    unqualified = name_id_policy_from_string(
        '<NameIDPolicy xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Format="%s" AllowCreate="true"/>'
        % NAMEID_FORMAT_PERSISTENT
    )
    out_a = db.handle_name_id_mapping_request(id_a, unqualified)
    out_b = db.handle_name_id_mapping_request(id_b, unqualified)
    show("mapping A ->", (out_a.format, out_a.text, out_a.sp_name_qualifier))
    show("mapping B ->", (out_b.format, out_b.text, out_b.sp_name_qualifier))
    show("A and B got identical protocol NameID", out_a.text == out_b.text)
    show("reverse lookup still returns", db.find_local_id(out_a))
    show("forward record for alice", db.db["alice"])

    section("NameIDMapping accepts a cross-SP qualified target")
    db = IdentDB({}, name_qualifier=IDP)
    db.store("alice", id_a)
    db.store("alice", id_b)
    cross = NameIDPolicy(format=NAMEID_FORMAT_PERSISTENT, allow_create="true", sp_name_qualifier=SP_B)
    out = db.handle_name_id_mapping_request(id_a, cross)
    show("A asks format + SNQ=SP-B ->", (out.format, out.text, out.sp_name_qualifier))
    show("returned B's exact NameID", out.text == id_b.text)


def logout_and_relogin():
    section("Persistent NameID survives logout and maps to same text")
    idp = Server(config=IdPConfig().load(server_config()))
    policy = NameIDPolicy(format=NAMEID_FORMAT_PERSISTENT)
    first = issue(idp, SP_A, policy, "alice", "p1")
    idp.clean_out_user(first)
    second = issue(idp, SP_A, policy, "alice", "p2")
    show("first persistent", (first.format, first.text))
    show("second persistent after clean_out_user", (second.format, second.text))
    show("same text", first.text == second.text)
    show("ident DB still contains mapping keys", sorted(idp.ident.db.keys()))

    section("Transient is reused because both find_nameid and match_local_id see old rows")
    tpolicy = NameIDPolicy(format=NAMEID_FORMAT_TRANSIENT)
    t1 = issue(idp, SP_A, tpolicy, "alice", "t1")
    t2 = issue(idp, SP_A, tpolicy, "alice", "t2")
    show("first transient", (t1.format, t1.text))
    show("second transient", (t2.format, t2.text))
    show("same text across logins", t1.text == t2.text)
    show("find_nameid format=transient", [(x.format, x.text) for x in idp.ident.find_nameid("alice", sp_name_qualifier=SP_A, format=NAMEID_FORMAT_TRANSIENT)])

    section("SessionStorage key is the full NameID code, not the reverse key")
    storage = SessionStorage()
    stored = NameID(format=NAMEID_FORMAT_PERSISTENT, text=first.text, sp_name_qualifier=SP_A, name_qualifier=IDP)
    forged = NameID(format=NAMEID_FORMAT_PERSISTENT, text=first.text, sp_name_qualifier=SP_B, name_qualifier=IDP)
    from saml2.saml import Assertion, AuthnStatement, Subject

    storage.store_assertion(
        Assertion(id="assert-A", subject=Subject(name_id=stored), authn_statement=[AuthnStatement(session_index="_a")]),
        [],
    )
    show("session key stored", sha1(code_binary(stored)).hexdigest())
    show("session key forged", sha1(code_binary(forged)).hexdigest())
    try:
        storage.remove_authn_statements(forged)
        print("  remove_authn_statements(forged) unexpectedly succeeded")
    except KeyError as exc:
        show("remove_authn_statements(forged) KeyError", exc)
    show("reverse lookup of forged", idp.ident.find_local_id(forged))
    show("clean_out_user(forged) local id", idp.clean_out_user(forged))
    idp.close()


def main():
    print("pysaml2 NameID scope reproduction")
    print("NameID attribute order used by code(): NameQualifier, SPNameQualifier, Format, SPProvidedID, text")
    local_identdb()
    server_first_issue_and_allow_create()
    policy_helpers()
    logout_and_relogin()
    print("\nDone.  No pysaml2 source was modified.")


if __name__ == "__main__":
    main()
