"""Explainable, single-pass attribute release decisions for the IdP.

The :class:`AttributeReleasePolicy` combines, in one decision, the three
inputs that decide which values are released to a relying party:

* the IdP's local ``attribute_restrictions`` (regular expressions), which can
  only ever *reduce* what is released,
* the entity-category based allow-list (if any), and
* the SP's ``RequestedAttribute`` entries, whose formal ``Name`` is converted
  to a local attribute name through the configured attribute converters.

Remote metadata can never widen the local allow-list.  The decision keeps an
explanation of what was released, what was filtered and why a required value
could not be provided.  Filtered *values* are only counted; their raw contents
never end up in the explanation so that sensitive data is not leaked through
logs.
"""

from saml2.attribute_converter import get_local_name


# Reason codes used in the explanation.  They intentionally describe *why* a
# value or attribute was withheld without ever containing the value itself.
REASON_NOT_REQUESTED = "not_requested"
REASON_NOT_ALLOWED_ENTITY_CATEGORY = "not_allowed_by_entity_category"
REASON_NOT_ALLOWED_LOCAL = "not_allowed_by_local_restriction"
REASON_SP_VALUE_NOT_MATCHED = "requested_value_not_present"
REASON_MISSING_ATTRIBUTE = "required_attribute_missing"
REASON_EMPTY_ATTRIBUTE = "required_attribute_empty"
REASON_NO_ALLOWED_VALUE = "required_value_filtered"


def _as_list(values):
    """Normalise an AVA value into a list without treating strings as sequences."""
    if values is None:
        return []
    if isinstance(values, (list, tuple, set)):
        return list(values)
    return [values]


class AttributeReleaseDecision:
    """The outcome of evaluating the release policy for one SP.

    The object is intentionally value-free when it comes to withheld data:
    ``filtered`` and ``missing`` only carry attribute names, reason codes and
    counts, never the attribute values that were removed.
    """

    def __init__(self, sp_entity_id):
        self.sp_entity_id = sp_entity_id
        # The attribute/value pairs that the IdP is actually allowed to release.
        self.allowed = {}
        # Per attribute, the reasons that withheld values were dropped with a
        # count of the affected values::
        #   {"mail": {"not_allowed_by_local_restriction": 1}}
        self.filtered = {}
        # Required attributes that could not be satisfied, with a reason code.
        self.missing = []

    def record_filtered(self, attribute, reason, count=1):
        if count <= 0:
            return
        bucket = self.filtered.setdefault(attribute, {})
        bucket[reason] = bucket.get(reason, 0) + count

    def record_missing(self, attribute, reason, requested_name=None):
        entry = {"attribute": attribute, "reason": reason}
        if requested_name is not None:
            entry["requested_name"] = requested_name
        if entry not in self.missing:
            self.missing.append(entry)

    @property
    def released(self):
        """Alias for the attributes that will be released."""
        return self.allowed

    def is_satisfied(self):
        """Return ``True`` when every required attribute could be satisfied."""
        return not self.missing

    def explanation(self):
        """Return a serialisable, value-free explanation of the decision."""
        return {
            "sp_entity_id": self.sp_entity_id,
            "released": {attribute: len(_as_list(values)) for attribute, values in self.allowed.items()},
            "released_attributes": sorted(self.allowed.keys()),
            "filtered": {attribute: dict(reasons) for attribute, reasons in self.filtered.items()},
            "missing": [dict(entry) for entry in self.missing],
        }


class AttributeReleasePolicy:
    """Compute a single, explainable attribute release decision."""

    def __init__(self, acs=None, fail_on_missing_requested=True):
        self.acs = acs or []
        self.fail_on_missing_requested = fail_on_missing_requested

    # -- name resolution ---------------------------------------------------

    def _resolve_local_name(self, requested):
        """Map a RequestedAttribute dict to a canonical local attribute name.

        The formal ``Name`` in the declared ``NameFormat`` is authoritative.
        The ``FriendlyName`` is only a fallback for names the converters cannot
        map, so a FriendlyName that disagrees with the formal Name cannot reach
        a different local attribute.  An empty string is treated as "no name".
        """
        name = (requested.get("name") or "").strip()
        name_format = requested.get("name_format") or ""
        friendly = (requested.get("friendly_name") or "").strip()

        local = get_local_name(self.acs, name, name_format) if name else None
        if local:
            return local.strip(), name
        if friendly:
            return friendly, name
        return name, name

    @staticmethod
    def _find_ava_key(ava, local_name):
        """Find the actual AVA key using exact then case-insensitive match."""
        if not local_name:
            return None
        if local_name in ava:
            return local_name
        lowered = local_name.lower()
        for key in ava:
            if key.lower() == lowered:
                return key
        return None

    # -- value filtering ---------------------------------------------------

    @staticmethod
    def _match_local_restriction(values, restrictions):
        """Split values into (allowed, dropped_count) using compiled regexps."""
        allowed = []
        for value in values:
            if isinstance(value, str) and not any(pattern.match(value) for pattern in restrictions):
                continue
            allowed.append(value)
        return allowed, len(values) - len(allowed)

    @staticmethod
    def _match_requested_values(values, requested_values):
        """Keep only values explicitly enumerated by the SP.

        An empty enumeration means "any value", matching the wire semantics.
        """
        if not requested_values:
            return list(values), 0
        allowed = [value for value in values if value in requested_values]
        return allowed, len(values) - len(allowed)

    # -- main entry point --------------------------------------------------

    def decide(
        self,
        ava,
        sp_entity_id,
        required=None,
        optional=None,
        entity_category_allowlist=None,
        attribute_restrictions=None,
    ):
        """Evaluate all release constraints in a single pass.

        :param ava: the subject's attribute value assertion (local names)
        :param sp_entity_id: the relying party entity ID (for the explanation)
        :param required: list of required RequestedAttribute dicts
        :param optional: list of optional RequestedAttribute dicts
        :param entity_category_allowlist: iterable of local attribute names the
            entity categories permit.  ``None`` disables the category gate; an
            empty iterable enables the gate but allows nothing.
        :param attribute_restrictions: mapping of lower-cased local attribute
            name to a list of compiled regular expressions, or ``None``
        :return: an :class:`AttributeReleaseDecision`
        """
        required = required or []
        optional = optional or []
        decision = AttributeReleaseDecision(sp_entity_id)

        ava = {key: _as_list(value) for key, value in ava.items()}
        restrictions = attribute_restrictions or {}

        category_gate = entity_category_allowlist is not None
        category_allowed = {name.lower() for name in (entity_category_allowlist or [])}
        # A non-empty attribute_restrictions mapping is itself an attribute
        # allow-list: any attribute that is not listed is withheld.  ``None``
        # means "release everything I have" and disables that gate.
        local_gate = bool(restrictions)
        local_allowed = {name.lower() for name in restrictions}
        remote_requested = bool(required or optional)

        # Phase 1: canonicalise every RequestedAttribute.  Entries that resolve
        # to the same local attribute (e.g. the same Name expressed under two
        # NameFormats) are merged so they can never open a second, unrestricted
        # path to the same values.
        entries = {}

        def register(requested, is_required):
            local_name, requested_name = self._resolve_local_name(requested)
            ava_key = self._find_ava_key(ava, local_name) if local_name else None
            canonical = (ava_key or local_name or "").lower()
            if not canonical:
                return
            requested_values = [
                av["text"] for av in requested.get("attribute_value", []) if av.get("text")
            ]
            entry = entries.get(canonical)
            if entry is None:
                entries[canonical] = {
                    "local_name": local_name,
                    "ava_key": ava_key,
                    "requested_name": requested_name,
                    "values": list(requested_values),
                    "required": is_required,
                }
            else:
                if entry["ava_key"] is None and ava_key is not None:
                    entry["ava_key"] = ava_key
                for value in requested_values:
                    if value not in entry["values"]:
                        entry["values"].append(value)
                entry["required"] = entry["required"] or is_required

        for requested_attr in required:
            register(requested_attr, True)
        for requested_attr in optional:
            register(requested_attr, False)

        def name_is_releasable(lowered):
            # Every active gate must permit the attribute.  Remote requests can
            # only narrow the local/category allow-list, never widen it.  When an
            # entity category drives the decision the category allow-list defines
            # the releasable set, so unrequested but permitted attributes stay.
            if local_gate and lowered not in local_allowed:
                return False
            if category_gate and lowered not in category_allowed:
                return False
            if remote_requested and not category_gate and lowered not in entries:
                return False
            return True

        # Phase 2: evaluate every attribute the subject actually has.
        for ava_key, values in ava.items():
            lowered = ava_key.lower()
            entry = entries.get(lowered)

            if not name_is_releasable(lowered):
                if local_gate and lowered not in local_allowed:
                    reason = REASON_NOT_ALLOWED_LOCAL
                elif category_gate and lowered not in category_allowed:
                    reason = REASON_NOT_ALLOWED_ENTITY_CATEGORY
                else:
                    reason = REASON_NOT_REQUESTED
                decision.record_filtered(ava_key, reason, len(values))
                if entry and entry["required"] and self.fail_on_missing_requested:
                    decision.record_missing(entry["local_name"], reason, entry["requested_name"])
                continue

            survivors = list(values)

            if not survivors:
                # Present but empty is distinct from absent.
                if entry and entry["required"] and self.fail_on_missing_requested:
                    decision.record_missing(entry["local_name"], REASON_EMPTY_ATTRIBUTE, entry["requested_name"])
                continue

            emptied_by = None
            local_rules = restrictions.get(lowered)
            if local_rules:
                survivors, dropped = self._match_local_restriction(survivors, local_rules)
                decision.record_filtered(ava_key, REASON_NOT_ALLOWED_LOCAL, dropped)
                if not survivors:
                    emptied_by = REASON_NOT_ALLOWED_LOCAL

            if survivors and entry is not None and entry["values"]:
                survivors, dropped = self._match_requested_values(survivors, entry["values"])
                decision.record_filtered(ava_key, REASON_SP_VALUE_NOT_MATCHED, dropped)
                if not survivors and emptied_by is None:
                    emptied_by = REASON_SP_VALUE_NOT_MATCHED

            if survivors:
                decision.allowed[ava_key] = survivors
            elif entry and entry["required"] and self.fail_on_missing_requested:
                reason = REASON_NO_ALLOWED_VALUE if emptied_by == REASON_NOT_ALLOWED_LOCAL else emptied_by
                decision.record_missing(
                    entry["local_name"], reason or REASON_NO_ALLOWED_VALUE, entry["requested_name"]
                )

        # Phase 3: required attributes that the subject does not have at all.
        for lowered, entry in entries.items():
            if entry["ava_key"] is not None:
                continue
            if not self.fail_on_missing_requested or not entry["required"]:
                continue
            if local_gate and lowered not in local_allowed:
                decision.record_missing(entry["local_name"], REASON_NOT_ALLOWED_LOCAL, entry["requested_name"])
            elif category_gate and lowered not in category_allowed:
                decision.record_missing(
                    entry["local_name"], REASON_NOT_ALLOWED_ENTITY_CATEGORY, entry["requested_name"]
                )
            else:
                decision.record_missing(entry["local_name"], REASON_MISSING_ATTRIBUTE, entry["requested_name"])

        return decision
