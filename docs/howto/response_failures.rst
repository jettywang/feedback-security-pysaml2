.. _response_failures:

Handling structured response failures
=====================================

A login gateway has to distinguish three very different situations:

* the user has not completed the required authentication (for example
  ``NoAuthnContext`` or ``NoPassive``),
* the IdP cannot satisfy the requested authentication strength, and
* the protocol response itself cannot be trusted (malformed XML or a
  bad/missing signature).

Raising one generic exception for all of them makes that distinction
impossible at the business layer. PySAML2 therefore attaches a structured
:class:`~saml2.failure.SAMLFailure` to every response processing exception.
The legacy exception classes and their raising points are unchanged, so
existing ``except`` blocks keep working.

Failure categories
------------------

Every failure has a :class:`~saml2.failure.FailureCategory`:

``malformed``
    The message could not be parsed or schema validated. Never trusted.

``signature``
    The message was parseable but could not be authenticated (missing,
    invalid or untrusted signature). Never trusted. The self-asserted
    status inside such a message is kept for diagnostics only.

``status``
    A parsed response carrying a non-success SAML status. It is only a
    genuine IdP reported business failure when ``trusted`` is ``True``,
    which requires a verified signature.

``SAMLFailure`` exposes:

* ``status_codes`` - the full, possibly nested, ``StatusCode`` chain with
  the top level code first,
* ``in_response_to``, ``response_id`` and ``issuer`` for request
  correlation,
* ``public_reason`` - a fixed-vocabulary, user/log safe reason such as
  ``unsupported_authn_context`` or ``passive_login_not_possible``,
* ``trusted`` and the convenience flag ``is_business_failure``, and
* ``raw_status_message`` - the issuer supplied free text, retained for
  authenticated server-side diagnostics only.

The raw ``StatusMessage`` is deliberately excluded from
``public_reason`` and from exception messages: it is attacker-influenced
text and must never be rendered on a web page or written verbatim to a
log.

Why unauthenticated statuses can not downgrade login
----------------------------------------------------

An attacker can take a genuinely signed ``NoPassive``/``NoAuthnContext``
response, strip or break its signature and replay it. Because the status
is only self-asserted at that point, PySAML2 marks the failure as
untrusted. A response whose signature did not verify can never set
``is_business_failure`` to ``True``, so it can never select a weaker
login flow. Only an authenticated status failure reaches the business
prompt branch; everything else stays in the protocol rejection branch.

Backend example
---------------

.. code-block:: python

    from saml2.failure import FailureCategory

    def handle_acs(post_body, outstanding_queries):
        try:
            response = client.parse_authn_request_response(
                post_body["SAMLResponse"], BINDING_HTTP_POST, outstanding_queries
            )
        except Exception as exc:
            failure = getattr(exc, "failure", None)
            if failure is None:
                # Defensive fallback for exceptions raised outside the
                # SAML pipeline; never trust a payload here either.
                return render("login_error", reason="request_failed"), 400

            if failure.is_business_failure:
                # Authenticated IdP status: safe to drive a business flow.
                # Render a fixed, localised message keyed by public_reason;
                # never output failure.raw_status_message.
                if failure.public_reason == "unsupported_authn_context":
                    return redirect("/login/step-up-mfa")
                if failure.public_reason == "passive_login_not_possible":
                    return render("login", passive_unavailable=True)
                return render("login_error", reason=failure.public_reason)

            # Protocol rejection branch: malformed (FailureCategory.MALFORMED)
            # or unauthenticated (FailureCategory.SIGNATURE) responses.
            # Log the fixed reason and correlation IDs only, keep the raw
            # message out of the log and the page.
            security_log.warning(
                "rejected SAML response category=%s reason=%s in_response_to=%s issuer=%s",
                failure.category.value,
                failure.public_reason,
                failure.in_response_to,
                failure.issuer,
            )
            return render("login_error", reason="request_failed"), 400

        return establish_session(response)

The same ``exc.failure`` object is available on the legacy exception
classes (for example ``StatusNoAuthnContext`` or ``SignatureError``), so
callers that already catch those classes can read the structured result
without changing their exception layout.
