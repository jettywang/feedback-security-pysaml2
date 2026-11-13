"""Pytest wrapper for the offline KeyDescriptor selection experiment.

The assertions here mirror the findings documented in
security-review/REVIEW.md. The experiment itself generates all key material
in memory and performs no network access; xmlsec1 is required on PATH for
the end-to-end cases (S6, S6-neg, S8).
"""
import pytest

from experiment_cert_selection import RESULTS
import experiment_cert_selection as experiment


@pytest.fixture(scope="module", autouse=True)
def run_experiment():
    experiment.RESULTS.clear()
    rc = experiment.main()
    assert rc == 1, "experiment is expected to report confirmed problems"
    return experiment.RESULTS


def _by_id(case_id):
    return next(item for item in RESULTS if item[0] == case_id)


@pytest.mark.parametrize("case_id", ["S1a", "S1b", "S1c", "S2a", "S2b", "S4", "S6-neg", "S8"])
def test_safe_combinations(case_id):
    assert _by_id(case_id)[1] == "SAFE"


@pytest.mark.parametrize("case_id", ["S1d", "S1e", "S3a", "S3b", "S5", "S6", "S9"])
def test_confirmed_problems(case_id):
    assert _by_id(case_id)[1] == "PROBLEM"


def test_metadata_signature_prerequisite_recorded():
    assert _by_id("S7")[1] == "NOTE"
