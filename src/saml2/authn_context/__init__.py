from saml2 import extension_elements_to_elements
from saml2.authn_context import ippword
from saml2.authn_context import mobiletwofactor
from saml2.authn_context import ppt
from saml2.authn_context import pword
from saml2.authn_context import sslcert
from saml2.authn_strength import AuthnContextStrength
from saml2.authn_strength import context_matches
from saml2.authn_strength import requested_class_refs
from saml2.authn_strength import requested_decl_refs
from saml2.saml import AuthnContext
from saml2.saml import AuthnContextClassRef
from saml2.samlp import RequestedAuthnContext


UNSPECIFIED = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"

INTERNETPROTOCOLPASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:InternetProtocolPassword"
MOBILETWOFACTORCONTRACT = "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract"
PASSWORDPROTECTEDTRANSPORT = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
PASSWORD = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
TLSCLIENT = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
TIMESYNCTOKEN = "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken"

AL1 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel1"
AL2 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel2"
AL3 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel3"
AL4 = "http://idmanagement.gov/icam/2009/12/saml_2.0_profile/assurancelevel4"

CMP_TYPE = ["exact", "minimum", "maximum", "better"]


class AuthnBroker:
    def __init__(self, authn_context_strength=None):
        self.db = {"info": {}, "key": {}}
        self.next = 0
        self.strength = AuthnContextStrength.from_config(authn_context_strength)

    @staticmethod
    def exact(a, b):
        return a == b

    @staticmethod
    def minimum(a, b):
        return b >= a

    @staticmethod
    def maximum(a, b):
        return b <= a

    @staticmethod
    def better(a, b):
        return b > a

    def add(self, spec, method, level=0, authn_authority="", reference=None):
        """
        Adds a new authentication method.
        Assumes not more than one authentication method per AuthnContext
        specification.

        :param spec: What the authentication endpoint offers in the form
            of an AuthnContext
        :param method: A identifier of the authentication method.
        :param level: security level, positive integers, 0 is lowest
        :param reference: Desired unique reference to this `spec'
        :return:
        """

        if spec.authn_context_class_ref:
            key = spec.authn_context_class_ref.text
            _info = {"class_ref": key, "method": method, "level": level, "authn_auth": authn_authority}
        elif spec.authn_context_decl:
            key = spec.authn_context_decl.c_namespace
            _info = {"method": method, "decl": spec.authn_context_decl, "level": level, "authn_auth": authn_authority}
        else:
            raise NotImplementedError()

        self.next += 1
        _ref = reference
        if _ref is None:
            _ref = str(self.next)

        if _ref in self.db["info"]:
            raise Exception("Internal error: reference is not unique")

        self.db["info"][_ref] = _info
        try:
            self.db["key"][key].append(_ref)
        except KeyError:
            self.db["key"][key] = [_ref]

    def remove(self, spec, method=None, level=0, authn_authority=""):
        if spec.authn_context_class_ref:
            _cls_ref = spec.authn_context_class_ref.text
            try:
                _refs = self.db["key"][_cls_ref]
            except KeyError:
                return
            else:
                _remain = []
                for _ref in _refs:
                    item = self.db["info"][_ref]
                    if method and method != item["method"]:
                        _remain.append(_ref)
                    if level and level != item["level"]:
                        _remain.append(_ref)
                    if authn_authority and authn_authority != item["authn_authority"]:
                        _remain.append(_ref)
                if _remain:
                    self.db[_cls_ref] = _remain

    def _pick_by_class_ref(self, cls_ref, comparision_type="exact"):
        """Pick candidates for a single class reference.

        Without a configured partial order this keeps the historical
        integer level behaviour.  With a partial order, candidates are
        those that satisfy the comparison against ``cls_ref``.  They are
        ordered by the number of contexts that are stronger than the
        candidate, with the configured reference order as a tie breaker.
        This makes the order stable while never treating an incomparable
        context as a substitute.
        """
        if self.strength.contexts:
            return self._pick_partial(cls_ref, comparision_type)

        func = getattr(self, comparision_type)
        try:
            _refs = self.db["key"][cls_ref]
        except KeyError:
            return []
        else:
            _item = self.db["info"][_refs[0]]
            _level = _item["level"]
            if comparision_type != "better":
                if _item["method"]:
                    res = [(_item["method"], _refs[0])]
                else:
                    res = []
            else:
                res = []

            for ref in _refs[1:]:
                item = self.db["info"][ref]
                res.append((item["method"], ref))
                if func(_level, item["level"]):
                    _level = item["level"]
            for ref, _dic in self.db["info"].items():
                if ref in _refs:
                    continue
                elif func(_level, _dic["level"]):
                    if _dic["method"]:
                        _val = (_dic["method"], ref)
                        if _val not in res:
                            res.append(_val)
            return res

    def _qualified_candidates(self, requested_refs, comparison, kind="class"):
        """Return qualified candidates as ``(rank, order, method, ref)``."""
        if isinstance(requested_refs, str):
            requested_refs = [requested_refs]
        unrestricted = UNSPECIFIED in requested_refs

        candidates = []
        for ref, item in self.db["info"].items():
            if not item["method"]:
                continue
            if kind == "class":
                context = item.get("class_ref")
            else:
                context = getattr(item.get("decl"), "c_namespace", None)
            if context is None:
                continue
            if not unrestricted and not self.strength.satisfies(comparison, context, requested_refs):
                continue
            candidates.append(
                (
                    self.strength.rank(context),
                    self._reference_order(ref),
                    item["method"],
                    ref,
                )
            )
        return candidates

    def _pick_partial(self, requested_refs, comparison, kind="class"):
        """Pick candidates using the configured partial order.

        ``kind`` selects which stored context is compared: ``"class"``
        compares the context class reference, ``"decl"`` compares the
        declaration's namespace.  Class references and declaration
        references are never compared with each other.

        Candidate order is deterministic:

        1. contexts that satisfy the comparison,
        2. fewer stronger contexts first (weaker, and thus less disruptive,
           choices first for ``minimum``; ``better`` already requires
           strict strength),
        3. insertion order of the broker.

        The tie breaker only orders candidates that are already qualified;
        it never lets an incomparable context pass the comparison.
        """
        candidates = self._qualified_candidates(requested_refs, comparison, kind)
        candidates.sort(key=lambda candidate: (candidate[0], candidate[1]))
        return [(method, ref) for _, _, method, ref in candidates]

    def _reference_order(self, ref):
        try:
            return int(ref)
        except (TypeError, ValueError):
            return self.next

    def pick(self, req_authn_context=None):
        """
        Given the authentication context find zero or more places where
        the user could be sent next. Ordered according to security level
        or, when configured, to the strength partial order.

        :param req_authn_context: The requested context as an
            RequestedAuthnContext instance
        :return: list of ``(method, reference)`` tuples
        """

        if req_authn_context is None:
            return self._pick_by_class_ref(UNSPECIFIED, "minimum")

        if self.strength.contexts:
            return self._pick_partial_request(req_authn_context)

        # No partial order configured: keep the historical integer level
        # behaviour and its handling of multiple references unchanged.
        if req_authn_context.authn_context_class_ref:
            if req_authn_context.comparison:
                _cmp = req_authn_context.comparison
            else:
                _cmp = "exact"
            if _cmp == "exact":
                res = []
                for cls_ref in req_authn_context.authn_context_class_ref:
                    res += self._pick_by_class_ref(cls_ref.text, _cmp)
                return res
            else:
                return self._pick_by_class_ref(req_authn_context.authn_context_class_ref[0].text, _cmp)
        elif req_authn_context.authn_context_decl_ref:
            if req_authn_context.comparison:
                _cmp = req_authn_context.comparison
            else:
                _cmp = "exact"
            return self._pick_by_class_ref(req_authn_context.authn_context_decl_ref, _cmp)

    def _pick_partial_request(self, req_authn_context):
        """Pick candidates for a request using the partial order.

        A request may list several class references.  They are alternatives
        for ``exact``, ``minimum`` and ``maximum``; ``better`` requires a
        context strictly stronger than every listed reference.  The same
        rule is implemented once in
        :meth:`saml2.authn_strength.AuthnContextStrength.satisfies` and
        applied here per reference kind.

        Candidates from the class reference group are returned before
        declaration reference candidates; within each group the order is
        the deterministic order from :meth:`_pick_partial`.  Duplicate
        method references are removed, keeping the first occurrence.
        """
        comparison = req_authn_context.comparison or "exact"
        candidates = []

        for refs, kind in (
            (requested_class_refs(req_authn_context), "class"),
            (requested_decl_refs(req_authn_context), "decl"),
        ):
            if not refs:
                continue
            candidates.extend(self._qualified_candidates(refs, comparison, kind))

        # One request with several class references describes alternatives.
        # Every candidate that satisfies the comparison against at least
        # one reference is eligible.  Ordering is independent of which
        # reference matched: candidates with fewer stronger contexts come
        # first and broker insertion order breaks ties.
        candidates.sort(key=lambda candidate: (candidate[0], candidate[1]))

        result = []
        seen = set()
        for _, _, method, reference in candidates:
            if reference in seen:
                continue
            seen.add(reference)
            result.append((method, reference))
        return result

    def match(self, requested, provided):
        """Compare two contexts using the configured partial order.

        ``requested`` may be a ``RequestedAuthnContext`` or a context
        reference string.  ``provided`` may be an ``AuthnContext`` or a
        string.  Without a configured order this keeps the historical
        equality check.
        """
        if self.strength.contexts:
            if isinstance(provided, str):
                provided = AuthnContext(authn_context_class_ref=AuthnContextClassRef(text=provided))
            return context_matches(requested, provided, self.strength)
        return requested == provided

    def __getitem__(self, ref):
        return self.db["info"][ref]

    def get_authn_by_accr(self, accr):
        _ids = self.db["key"][accr]
        return self[_ids[0]]


def authn_context_factory(text):
    # brute force
    for mod in [ippword, mobiletwofactor, ppt, pword, sslcert]:
        inst = mod.authentication_context_declaration_from_string(text)
        if inst:
            return inst

    return None


def authn_context_decl_from_extension_elements(extelems):
    res = extension_elements_to_elements(extelems, [ippword, mobiletwofactor, ppt, pword, sslcert])
    try:
        return res[0]
    except IndexError:
        return None


def authn_context_class_ref(ref):
    return AuthnContext(authn_context_class_ref=AuthnContextClassRef(text=ref))


def requested_authn_context(class_ref, comparison="minimum"):
    if not isinstance(class_ref, list):
        class_ref = [class_ref]
    return RequestedAuthnContext(
        authn_context_class_ref=[AuthnContextClassRef(text=i) for i in class_ref], comparison=comparison
    )
