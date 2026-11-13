from hashlib import sha1
import logging

from saml2.authn_strength import AuthnContextStrength
from saml2.authn_strength import context_matches
from saml2.authn_strength import explain_context_mismatch
from saml2.ident import code_binary


logger = logging.getLogger(__name__)


def context_match(cfilter, cntx, strength=None):
    """Check that an authentication context matches a request.

    ``strength`` is the optional partial order.  When it is ``None`` the
    historical behaviour of accepting any context is preserved.  Callers
    that pass an assertion's ``AuthnContext`` get the same comparison
    semantics used when selecting an authentication method.
    """
    return context_matches(cfilter, cntx, strength)


# The key to the stored authn statement is placed encrypted in the cookie


class SessionStorage:
    """In memory storage of session information"""

    def __init__(self, authn_context_strength=None):
        self.db = {"assertion": {}, "authn": {}}
        self.assertion = self.db["assertion"]
        self.authn = self.db["authn"]
        self.strength = AuthnContextStrength.from_config(authn_context_strength)

    def store_assertion(self, assertion, to_sign):
        self.assertion[assertion.id] = (assertion, to_sign)
        key = sha1(code_binary(assertion.subject.name_id)).hexdigest()
        try:
            self.authn[key].append(assertion.authn_statement)
        except KeyError:
            self.authn[key] = [assertion.authn_statement]

    def get_assertion(self, cid):
        return self.assertion[cid]

    def _statements_for(self, name_id):
        key = sha1(code_binary(name_id)).hexdigest()
        try:
            return self.authn[key]
        except KeyError:
            logger.info("Unknown subject %s", name_id)
            return []

    def _statement_matches(self, statement, session_index, requested_context):
        if session_index:
            if statement.session_index != session_index:
                return False
        if requested_context:
            return context_match(requested_context, statement.authn_context, self.strength)
        return True

    def get_authn_statements(self, name_id, session_index=None, requested_context=None):
        """Return stored statements that satisfy the session and context filters.

        ``requested_context`` is optional.  When it is given together with
        a configured partial order the statement's authentication context
        must satisfy the request; cached sessions are therefore re-checked
        on every reuse, not only on the first redirect.
        """
        result = []
        for statement in self._statements_for(name_id):
            if any(self._statement_matches(item, session_index, requested_context) for item in statement):
                result.append(statement)
        return result

    def explain_authn_statements(self, name_id, session_index=None, requested_context=None):
        """Explain why each stored statement is or is not reusable.

        Returns a list of ``(session_index, context, accepted, reason)``
        tuples.  ``reason`` is empty for accepted statements and describes
        the failed comparison otherwise.  This is meant for audit logging
        and for telling a caller why an existing login cannot satisfy a
        stronger request such as an MFA request.
        """
        explanations = []
        for statement in self._statements_for(name_id):
            for item in statement:
                accepted = self._statement_matches(item, session_index, requested_context)
                if accepted:
                    reason = ""
                else:
                    reason = explain_context_mismatch(requested_context, item.authn_context, self.strength)
                    if not reason and session_index:
                        reason = f"stored session index {item.session_index!r} does not match {session_index!r}"
                explanations.append((item.session_index, item.authn_context, accepted, reason))
        return explanations

    def remove_authn_statements(self, name_id):
        logger.debug("remove authn about: %s", name_id)
        nkey = sha1(code_binary(name_id)).hexdigest()

        del self.authn[nkey]
