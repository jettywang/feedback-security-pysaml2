# Feedback task starting environment

Upstream: https://github.com/IdentityPython/pysaml2
Upstream commit: `2fb5b50ad348e31f4847252c80261b89ccd9f053`
Prepared on macOS with the Python version recorded in the environment plan. No external database, queue, or cloud account is required.
System prerequisite: xmlsec1 (Homebrew libxmlsec1) is installed for XML signature checks.
The dependency file pins the installed runtime and test packages for the selected baseline. It is not a claim that all optional upstream test suites are installed.

From the repository root:

```sh
export NO_INTERNET=1 TZ=UTC UV_NO_CONFIG=1

uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -r .feedback/requirements.txt -e .
.venv/bin/python -m pytest -q -o addopts= tests/test_10_time_util.py tests/test_19_attribute_converter.py tests/test_77_authn_context.py tests/test_13_validate.py
```

Scope note: The scope is the command below, not all optional upstream integrations.

Observed baseline (2026-11-13): `51 passed in 3.39s`
Whole-command wall time: 3.630 seconds, exit code 0. This is one local measurement, not a runtime guarantee. The first install is excluded.

This seed adds preparation metadata only. Application sources and upstream tests are unchanged; there is no task solution in this commit.
