"""Partial ordering of SAML authentication context class references.

SAML's ``RequestedAuthnContext`` comparison values (``exact``, ``minimum``,
``maximum`` and ``better``) are defined in terms of an ordering between
authentication context class references.  The historical pysaml2
``AuthnBroker`` represented that ordering as a single integer "level" for
each authentication method.  An integer level can only express a total
order: every method is comparable with every other method.

Real deployments often have methods that have nothing to do with each
other.  A client certificate and an SMS one-time password, for example, are
both second factors but neither is a substitute for the other.  Treating
one as a higher integer level than the other silently allows such methods
to be substituted for each other.

This module adds an optional, explicitly configured partial order.  The
configuration maps an authentication context class reference to the class
references that are strictly stronger than it::

    {
        "urn:example:password": [
            "urn:example:sms",
            "urn:example:client-certificate",
        ],
        "urn:example:sms": ["urn:example:mfa"],
        "urn:example:client-certificate": ["urn:example:mfa"],
    }

The example above is a diamond.  ``sms`` and ``client-certificate`` are
both above ``password`` and below ``mfa``, but they are incomparable with
each other.  The order is transitive: the direct edges are closed before
any comparison is made.

When this configuration is absent, pysaml2 keeps its existing integer
level based behaviour.  When it is present, all four comparison values use
this partial order and incomparable contexts never satisfy one another.

The configuration is validated when it is loaded.  In particular a cycle
(for example ``a < b < c < a``) is rejected immediately instead of being
silently interpreted as an arbitrary total order.
"""

from collections.abc import Mapping

from saml2 import SAMLError


__all__ = [
    "AuthnContextStrengthError",
    "AuthnContextStrength",
    "ComparisonResult",
]


class AuthnContextStrengthError(SAMLError, ValueError):
    """Raised when a partial order configuration is invalid."""


class ComparisonResult:
    """Names for the four possible relations between two contexts."""

    SAME = "same"
    STRONGER = "stronger"
    WEAKER = "weaker"
    INCOMPARABLE = "incomparable"


def _normalise_edges(config):
    """Turn a configuration mapping into ``{weaker: set(stronger)}``."""
    if config is None:
        return {}
    if not isinstance(config, Mapping):
        raise AuthnContextStrengthError("authn_context_strength must be a mapping")

    edges = {}
    for weaker, stronger in config.items():
        if not isinstance(weaker, str) or not weaker:
            raise AuthnContextStrengthError("authn_context_strength keys must be non-empty strings")
        if isinstance(stronger, str):
            stronger = [stronger]
        try:
            stronger = list(stronger)
        except TypeError as exc:
            raise AuthnContextStrengthError(
                "authn_context_strength values must be a string or a list of strings"
            ) from exc

        for item in stronger:
            if not isinstance(item, str) or not item:
                raise AuthnContextStrengthError("authn_context_strength values must be non-empty strings")
            edges.setdefault(weaker, set()).add(item)

    return edges


class AuthnContextStrength:
    """A partial order over authentication context class references.

    The relation is configured as a directed graph where an edge from
    ``a`` to ``b`` means "``b`` is strictly stronger than ``a``".  Only the
    direct edges have to be configured; reachability supplies the transitive
    relation.

    The empty order is represented by ``contexts == set()``.  This is
    distinct from a configured order that happens to mention no contexts,
    and keeps the historical "accept any context" behaviour available to
    deployments that do not set the option.
    """

    def __init__(self, config=None):
        self._edges = _normalise_edges(config)
        self._contexts = set(self._edges)
        for targets in self._edges.values():
            self._contexts.update(targets)
        self._order = self._topological_order()
        self._reachable = self._transitive_closure()

    @classmethod
    def from_config(cls, config):
        """Build a strength order from a configuration value.

        An existing :class:`AuthnContextStrength` instance is returned
        unchanged, which makes it convenient to pass configuration values
        through several layers.
        """
        if isinstance(config, cls):
            return config
        return cls(config)

    # -- graph construction -------------------------------------------------

    def _topological_order(self):
        """Validate that the configured graph is acyclic and return a topo order."""
        visited = set()
        active = set()
        order = []

        def visit(node, path):
            if node in active:
                start = path.index(node)
                cycle = path[start:] + [node]
                raise AuthnContextStrengthError(
                    "authn_context_strength contains a cycle: " + " -> ".join(cycle)
                )
            if node in visited:
                return
            active.add(node)
            path.append(node)
            for target in self._edges.get(node, ()):
                visit(target, path)
            path.pop()
            active.remove(node)
            visited.add(node)
            order.append(node)

        for node in sorted(self._contexts):
            visit(node, [])
        return order

    def _transitive_closure(self):
        reachable = {node: set() for node in self._contexts}
        # ``_order`` lists stronger contexts before weaker ones, so each
        # successor's closure is complete by the time we reach its source.
        for node in self._order:
            for target in self._edges.get(node, ()):
                reachable[node].add(target)
                reachable[node].update(reachable[target])
        return reachable

    # -- relation -----------------------------------------------------------

    @property
    def contexts(self):
        """All context class references mentioned by the configuration."""
        return set(self._contexts)

    def relation(self, provided, requested):
        """Return the relation of ``provided`` to ``requested``.

        Returned values are the constants on :class:`ComparisonResult`.
        """
        if provided == requested:
            return ComparisonResult.SAME
        if provided in self._reachable.get(requested, ()):
            return ComparisonResult.STRONGER
        if requested in self._reachable.get(provided, ()):
            return ComparisonResult.WEAKER
        return ComparisonResult.INCOMPARABLE

    def is_stronger(self, provided, requested):
        """True if ``provided`` is strictly stronger than ``requested``."""
        return self.relation(provided, requested) == ComparisonResult.STRONGER

    def at_least_as_strong(self, provided, requested):
        """True if ``provided`` is at least as strong as ``requested``."""
        return self.relation(provided, requested) in (
            ComparisonResult.SAME,
            ComparisonResult.STRONGER,
        )

    def rank(self, context):
        """Return a deterministic strength rank usable for candidate ordering.

        Contexts that are incomparable can share a rank.  The rank is not
        used to decide whether one context may substitute another; it only
        orders candidates that have already passed :meth:`satisfies`.
        """
        return len(self._ancestors(context))

    def _ancestors(self, context):
        ancestors = set()
        for node, targets in self._reachable.items():
            if context in targets:
                ancestors.add(node)
        return ancestors

    # -- comparison semantics ----------------------------------------------

    def satisfies(self, comparison, provided, requested):
        """Check a provided context against a requested set.

        ``requested`` may be a single string or an iterable of strings.

        The comparison values have the same meaning as in SAML core, but
        interpreted over the partial order:

        ``exact``
            The provided context must equal one of the requested contexts.

        ``minimum``
            The provided context must be at least as strong as one of the
            requested contexts.  Listing several contexts describes
            alternatives; with a partial order there need not be a unique
            least element, so satisfying any listed floor is sufficient.

        ``maximum``
            The provided context must be no stronger than at least one
            requested context.  As with ``minimum``, several references
            describe ceilings and any ceiling is sufficient.

        ``better``
            The provided context must be strictly stronger than every
            requested context.  This is the partial-order counterpart of
            "stronger than the strongest requested context".
        """
        if isinstance(requested, str):
            requested = [requested]
        requested = list(requested or [])

        if comparison in (None, ""):
            comparison = "exact"
        if comparison not in ("exact", "minimum", "maximum", "better"):
            raise AuthnContextStrengthError(f"unknown comparison value: {comparison!r}")

        if not requested:
            # No requested context means no restriction.  This preserves
            # the historical behaviour of accepting every context.
            return True
        if comparison == "exact":
            return any(provided == item for item in requested)
        if comparison == "minimum":
            return any(self.at_least_as_strong(provided, item) for item in requested)
        if comparison == "maximum":
            return any(self.at_least_as_strong(item, provided) for item in requested)
        if comparison == "better":
            return all(self.is_stronger(provided, item) for item in requested)

        raise AuthnContextStrengthError(f"unknown comparison value: {comparison!r}")

    def explain(self, comparison, provided, requested):
        """Return a human readable explanation of a failed comparison.

        The return value is empty when the comparison succeeds.  It is
        intended for audit logs and for explaining why a cached
        authentication session cannot be reused for a stronger request.
        """
        if isinstance(requested, str):
            requested = [requested]
        requested = list(requested or [])

        if self.satisfies(comparison, provided, requested):
            return ""

        if comparison in (None, ""):
            comparison = "exact"
        if comparison not in ("exact", "minimum", "maximum", "better"):
            raise AuthnContextStrengthError(f"unknown comparison value: {comparison!r}")

        if not requested:
            return ""

        if provided is None:
            return "the authentication statement did not identify an authentication context"

        reasons = []
        for item in requested:
            relation = self.relation(provided, item)
            if comparison == "exact":
                if relation != ComparisonResult.SAME:
                    reasons.append(f"provided context {provided!r} is {relation} to requested {item!r}")
            elif comparison == "minimum":
                if not self.at_least_as_strong(provided, item):
                    if relation == ComparisonResult.INCOMPARABLE:
                        reasons.append(
                            f"provided context {provided!r} is incomparable with requested {item!r}; "
                            "incomparable authentication methods cannot substitute for each other"
                        )
                    else:
                        reasons.append(f"provided context {provided!r} is weaker than requested {item!r}")
            elif comparison == "maximum":
                if not self.at_least_as_strong(item, provided):
                    reasons.append(
                        f"provided context {provided!r} is stronger than the maximum allowed by requested {item!r}"
                    )
            elif comparison == "better":
                if not self.is_stronger(provided, item):
                    if relation == ComparisonResult.SAME:
                        reasons.append(
                            f"provided context {provided!r} is the same as requested {item!r}; "
                            "comparison 'better' requires a strictly stronger context"
                        )
                    elif relation == ComparisonResult.INCOMPARABLE:
                        reasons.append(
                            f"provided context {provided!r} is incomparable with requested {item!r}; "
                            "incomparable authentication methods cannot substitute for each other"
                        )
                    else:
                        reasons.append(f"provided context {provided!r} is weaker than requested {item!r}")

        return "; ".join(reasons)


# A short alias for call sites that prefer it.
AuthnStrength = AuthnContextStrength


def _element_text(value):
    """Return the text of a single SAML element or a plain string."""
    if value is None:
        return None
    text = getattr(value, "text", value)
    return text if isinstance(text, str) else None


def requested_class_refs(requested_authn_context):
    """Return the requested class references, or an empty list.

    ``AuthnContextDeclRef`` values are not class references and must not
    be compared with class references.  Keeping this helper separate
    prevents the broker from silently mixing the two.
    """
    if requested_authn_context is None or isinstance(requested_authn_context, str):
        return []
    values = getattr(requested_authn_context, "authn_context_class_ref", None) or []
    if not isinstance(values, (list, tuple)):
        values = [values]
    texts = []
    for value in values:
        text = _element_text(value)
        if text and text not in texts:
            texts.append(text)
    return texts


def requested_decl_refs(requested_authn_context):
    """Return the requested declaration references, or an empty list."""
    if requested_authn_context is None or isinstance(requested_authn_context, str):
        return []
    values = getattr(requested_authn_context, "authn_context_decl_ref", None) or []
    if not isinstance(values, (list, tuple)):
        values = [values]
    texts = []
    for value in values:
        text = _element_text(value)
        if text and text not in texts:
            texts.append(text)
    return texts


def _provided_by_kind(authn_context):
    """Return ``{"class": [...], "decl": [...]}`` for a provided context."""
    if authn_context is None:
        return {"class": [], "decl": []}
    return {
        "class": [text for text in [_element_text(getattr(authn_context, "authn_context_class_ref", None))] if text],
        "decl": [text for text in [_element_text(getattr(authn_context, "authn_context_decl_ref", None))] if text],
    }


def context_matches(requested, provided, strength):
    """Check a provided ``AuthnContext`` against a requested context.

    Kept as a module level helper so both session stores, the broker and
    callers that only have an assertion can apply the exact same rules.
    Class references are compared only with class references and
    declaration references only with declaration references.  A missing
    strength configuration keeps the historical pysaml2 behaviour of
    accepting any context.
    """
    if strength is None or not strength.contexts:
        return True

    comparison = getattr(requested, "comparison", None) or "exact"
    if isinstance(requested, str):
        provided_kinds = _provided_by_kind(provided)
        return any(
            strength.satisfies(comparison, item, [requested])
            for items in provided_kinds.values()
            for item in items
        )

    requested_kinds = {
        "class": requested_class_refs(requested),
        "decl": requested_decl_refs(requested),
    }
    unrestricted = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified" in (
        requested_kinds["class"] + requested_kinds["decl"]
    )
    if unrestricted:
        return True

    provided_kinds = _provided_by_kind(provided)
    for kind in ("class", "decl"):
        if requested_kinds[kind] and provided_kinds[kind]:
            if any(strength.satisfies(comparison, item, requested_kinds[kind]) for item in provided_kinds[kind]):
                return True
    return False


def explain_context_mismatch(requested, provided, strength):
    """Explain why a provided context does not satisfy the request."""
    if strength is None or not strength.contexts:
        return ""
    comparison = getattr(requested, "comparison", None) or "exact"
    if isinstance(requested, str):
        provided_kinds = _provided_by_kind(provided)
        if not any(provided_kinds.values()):
            return "the authentication statement did not identify an authentication context"
        reasons = []
        for items in provided_kinds.values():
            for item in items:
                reason = strength.explain(comparison, item, [requested])
                if reason:
                    reasons.append(reason)
        return "; ".join(reasons)

    provided_kinds = _provided_by_kind(provided)
    requested_kinds = {
        "class": requested_class_refs(requested),
        "decl": requested_decl_refs(requested),
    }
    if not any(provided_kinds.values()):
        return "the authentication statement did not identify an authentication context"
    if not any(requested_kinds.values()):
        return ""

    reasons = []
    for kind in ("class", "decl"):
        requested_refs = requested_kinds[kind]
        if not requested_refs:
            continue
        for item in provided_kinds[kind]:
            if strength.satisfies(comparison, item, requested_refs):
                return ""
            reason = strength.explain(comparison, item, requested_refs)
            if reason:
                reasons.append(reason)
    return "; ".join(reasons)
