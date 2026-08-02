import json
from pathlib import Path

from pydantic import ValidationError

from web_openness.models import (
    SCHEMA_VERSION,
    Confidence,
    DomainSnapshot,
    Observation,
    ObservationOutcome,
)
from web_openness.schema import SCHEMA_FILENAME, domain_snapshot_json_schema

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = PROJECT_ROOT / "schemas" / SCHEMA_FILENAME
FIXTURE_PATH = PROJECT_ROOT / "tests" / "fixtures" / f"domain_snapshot_v{SCHEMA_VERSION}.json"
LEGACY_SCHEMA_PATH = PROJECT_ROOT / "schemas" / "domain-snapshot-v0.1.0.json"
LEGACY_FIXTURE_PATH = PROJECT_ROOT / "tests" / "fixtures" / "domain_snapshot_v0.1.0.json"


def test_committed_schema_matches_runtime_model() -> None:
    committed = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    assert committed == domain_snapshot_json_schema()


def test_versioned_fixture_round_trips() -> None:
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    snapshot = DomainSnapshot.model_validate(payload)
    assert snapshot.model_dump(mode="json") == payload


def test_unknown_snapshot_fields_are_rejected() -> None:
    payload = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    payload["unversioned_field"] = True
    try:
        DomainSnapshot.model_validate(payload)
    except ValidationError as exc:
        assert "unversioned_field" in str(exc)
    else:
        raise AssertionError("unknown fields must not be silently discarded")


def test_previous_contract_artifacts_remain_available() -> None:
    assert json.loads(LEGACY_SCHEMA_PATH.read_text(encoding="utf-8"))["$id"].endswith(
        "domain-snapshot-v0.1.0.json"
    )
    assert json.loads(LEGACY_FIXTURE_PATH.read_text(encoding="utf-8"))["schema_version"] == "0.1.0"


def test_observation_outcome_and_confidence_cannot_conflict() -> None:
    try:
        Observation(
            value=None,
            outcome=ObservationOutcome.ERROR,
            confidence=Confidence.NO_EVIDENCE,
            confidence_score=0,
            method="inconsistent fixture",
        )
    except ValidationError as exc:
        assert "inconsistent" in str(exc)
    else:
        raise AssertionError("inconsistent observation outcome was accepted")
