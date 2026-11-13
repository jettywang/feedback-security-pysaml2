#!/usr/bin/env python
#

"""
Suppport for the client part of the SAML2.0 SOAP binding.
"""
import logging
import re
from xml.etree import ElementTree as ElementTree

import defusedxml.ElementTree

from saml2 import create_class_from_element_tree
from saml2.samlp import NAMESPACE as SAMLP_NAMESPACE
from saml2.schema import soapenv


logger = logging.getLogger(__name__)


class XmlParseError(Exception):
    pass


class WrongMessageType(Exception):
    pass


class InvalidSoapEnvelope(ValueError):
    """Raised when a SOAP envelope is ambiguous or structurally invalid."""


HEADER_TAG = "{%s}Header" % soapenv.NAMESPACE
BODY_TAG = "{%s}Body" % soapenv.NAMESPACE
ENVELOPE_TAG = "{%s}Envelope" % soapenv.NAMESPACE


def _envelope_parts(envelope):
    """Return the single SOAP Header and Body of an envelope.

    An envelope with zero or multiple Body elements is ambiguous and must not
    be interpreted. The same applies to multiple Header elements and to a
    Body that does not contain exactly one payload element.
    """
    if envelope.tag != ENVELOPE_TAG:
        raise InvalidSoapEnvelope(f"Invalid envelope tag '{envelope.tag}' should be '{ENVELOPE_TAG}'")

    headers = []
    bodies = []
    for part in envelope:
        if part.tag == HEADER_TAG:
            headers.append(part)
        elif part.tag == BODY_TAG:
            bodies.append(part)
        else:
            raise InvalidSoapEnvelope(f"Unexpected element '{part.tag}' in SOAP envelope")

    if len(bodies) != 1:
        raise InvalidSoapEnvelope(f"Expected exactly one SOAP Body, found {len(bodies)}")
    if len(headers) > 1:
        raise InvalidSoapEnvelope(f"Expected at most one SOAP Header, found {len(headers)}")

    body = bodies[0]
    if len(body) != 1:
        raise InvalidSoapEnvelope(f"Expected a single child element in SOAP Body, found {len(body)}")

    return headers, body


def parse_soap_enveloped_saml_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE, "{%s}LogoutResponse" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_logout_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE, "{%s}LogoutResponse" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_attribute_query(text):
    expected_tag = "{%s}AttributeQuery" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_attribute_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE, "{%s}AttributeResponse" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_logout_request(text):
    expected_tag = "{%s}LogoutRequest" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_authn_request(text):
    expected_tag = "{%s}AuthnRequest" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_artifact_resolve(text):
    expected_tag = "{%s}ArtifactResolve" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_artifact_response(text):
    expected_tag = "{%s}ArtifactResponse" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_name_id_mapping_request(text):
    expected_tag = "{%s}NameIDMappingRequest" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_name_id_mapping_response(text):
    expected_tag = "{%s}NameIDMappingResponse" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_manage_name_id_request(text):
    expected_tag = "{%s}ManageNameIDRequest" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_manage_name_id_response(text):
    expected_tag = "{%s}ManageNameIDResponse" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_assertion_id_request(text):
    expected_tag = "{%s}AssertionIDRequest" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_assertion_id_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE, "{%s}AssertionIDResponse" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_authn_query(text):
    expected_tag = "{%s}AuthnQuery" % SAMLP_NAMESPACE
    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_authn_query_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


def parse_soap_enveloped_saml_authn_response(text):
    tags = ["{%s}Response" % SAMLP_NAMESPACE]
    return parse_soap_enveloped_saml_thingy(text, tags)


# def parse_soap_enveloped_saml_logout_response(text):
#    expected_tag = '{%s}LogoutResponse' % SAMLP_NAMESPACE
#    return parse_soap_enveloped_saml_thingy(text, [expected_tag])


def parse_soap_enveloped_saml_thingy(text, expected_tags):
    """Parses a SOAP enveloped SAML thing and returns the thing as
    a string.

    :param text: The SOAP object as XML string
    :param expected_tags: What the tag of the SAML thingy is expected to be.
    :return: SAML thingy as a string
    """
    envelope = defusedxml.ElementTree.fromstring(text)

    _headers, body = _envelope_parts(envelope)

    saml_part = body[0]
    if saml_part.tag in expected_tags:
        return ElementTree.tostring(saml_part, encoding="UTF-8")
    else:
        raise WrongMessageType(f"Was '{saml_part.tag}' expected one of {expected_tags}")


NS_AND_TAG = re.compile(r"\{([^}]+)\}(.*)")


def instanciate_class(item, modules):
    m = NS_AND_TAG.match(item.tag)
    ns, tag = m.groups()
    for module in modules:
        if module.NAMESPACE == ns:
            try:
                target = module.ELEMENT_BY_TAG[tag]
                return create_class_from_element_tree(target, item)
            except KeyError:
                continue
    raise Exception(f"Unknown class: ns='{ns}', tag='{tag}'")


def class_instances_from_soap_enveloped_saml_thingies(text, modules):
    """Parses a SOAP enveloped header and body SAML thing and returns the
    thing as a dictionary class instance.

    :param text: The SOAP object as XML
    :param modules: modules representing xsd schemas
    :return: The body and headers as class instances
    """
    try:
        envelope = defusedxml.ElementTree.fromstring(text)
    except Exception as exc:
        raise XmlParseError(f"{exc}")

    headers, body = _envelope_parts(envelope)

    env = {"header": [], "body": instanciate_class(body[0], modules)}

    for header in headers:
        for item in header:
            env["header"].append(instanciate_class(item, modules))

    return env


def open_soap_envelope(text):
    """

    :param text: SOAP message
    :return: dictionary with two keys "body"/"header"
    """
    try:
        envelope = defusedxml.ElementTree.fromstring(text)
    except Exception as exc:
        raise XmlParseError(f"{exc}")

    headers, body = _envelope_parts(envelope)

    content = {"header": [], "body": ElementTree.tostring(body[0], encoding="UTF-8")}

    for header in headers:
        for item in header:
            content["header"].append(ElementTree.tostring(item, encoding="UTF-8"))

    return content


def make_soap_enveloped_saml_thingy(thingy, headers=None):
    """Returns a soap envelope containing a SAML request
    as a text string.

    :param thingy: The SAML thingy
    :return: The SOAP envelope as a string
    """
    soap_envelope = soapenv.Envelope()

    if headers:
        _header = soapenv.Header()
        _header.add_extension_elements(headers)
        soap_envelope.header = _header

    soap_envelope.body = soapenv.Body()
    soap_envelope.body.add_extension_element(thingy)

    return f"{soap_envelope}"


def soap_fault(message=None, actor=None, code=None, detail=None):
    """Create a SOAP Fault message

    :param message: Human readable error message
    :param actor: Who discovered the error
    :param code: Error code
    :param detail: More specific error message
    :return: A SOAP Fault message as a string
    """
    _string = _actor = _code = _detail = None

    if message:
        _string = soapenv.Fault_faultstring(text=message)
    if actor:
        _actor = soapenv.Fault_faultactor(text=actor)
    if code:
        _code = soapenv.Fault_faultcode(text=code)
    if detail:
        _detail = soapenv.Fault_detail(text=detail)

    fault = soapenv.Fault(
        faultcode=_code,
        faultstring=_string,
        faultactor=_actor,
        detail=_detail,
    )

    return f"{fault}"
