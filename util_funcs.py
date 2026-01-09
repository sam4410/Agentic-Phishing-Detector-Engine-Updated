# ========================================
# File: util_funcs.py
# ========================================
import json
import re
from urllib.parse import urlparse
from config import Config

def parse_coordinator_json(
    output: str,
    full_report: str = "",
    input_url: str = ""
):
    """
    STRICT parser for coordinator output.

    Responsibilities:
    - Validate JSON
    - Enforce schema & types
    - Attach combined report
    - Return coordinator output verbatim

    This function MUST NOT:
    - Recalculate risk
    - Modify scores
    - Infer intent
    - Override coordinator logic
    - Generate narratives
    """

    # -------------------------------------------------
    # Basic validation
    # -------------------------------------------------
    if not isinstance(output, str):
        raise RuntimeError(
            f"Unexpected coordinator output type: {type(output)}"
        )

    output = output.strip()
    if not output:
        raise RuntimeError("Coordinator returned empty output")

    try:
        result = json.loads(output)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            "Coordinator did not return valid JSON.\n\n"
            f"Raw output:\n{output}"
        ) from e

    if not isinstance(result, dict):
        raise RuntimeError("Coordinator JSON must be an object")

    # -------------------------------------------------
    # Required schema enforcement
    # -------------------------------------------------
    REQUIRED_FIELDS = {
        "final_risk_score": int,
        "verdict": str,
        "confidence": int,
        "ti_confirmed": bool,
        "signals": dict,
        "evidence": list,
        "top_findings": list,
        "recommendations": list,
        "summary": str
    }

    missing_fields = [
        field for field in REQUIRED_FIELDS
        if field not in result
    ]

    if missing_fields:
        raise RuntimeError(
            f"Coordinator JSON missing required fields: {missing_fields}"
        )

    # -------------------------------------------------
    # Type validation
    # -------------------------------------------------
    for field, expected_type in REQUIRED_FIELDS.items():
        if not isinstance(result[field], expected_type):
            raise RuntimeError(
                f"Field '{field}' must be of type "
                f"{expected_type.__name__}"
            )

    # -------------------------------------------------
    # Value validation
    # -------------------------------------------------
    if not (0 <= result["final_risk_score"] <= 100):
        raise RuntimeError(
            "final_risk_score must be between 0 and 100"
        )

    if not (0 <= result["confidence"] <= 100):
        raise RuntimeError(
            "confidence must be between 0 and 100"
        )

    if result["verdict"] not in {
        "malicious",
        "suspicious",
        "likely_benign"
    }:
        raise RuntimeError(
            f"Invalid verdict: {result['verdict']}"
        )

    # -------------------------------------------------
    # Signals validation (lightweight, non-opinionated)
    # -------------------------------------------------
    for signal_name, signal_data in result["signals"].items():
        if not isinstance(signal_data, dict):
            raise RuntimeError(
                f"Signal '{signal_name}' must be an object"
            )

        if "risk_score" not in signal_data:
            raise RuntimeError(
                f"Signal '{signal_name}' missing 'risk_score'"
            )

        if not isinstance(signal_data["risk_score"], int):
            raise RuntimeError(
                f"Signal '{signal_name}.risk_score' must be an integer"
            )

        if not (0 <= signal_data["risk_score"] <= 100):
            raise RuntimeError(
                f"Signal '{signal_name}.risk_score' out of range"
            )

    # -------------------------------------------------
    # Attach combined report (tools + coordinator)
    # -------------------------------------------------
    combined_report = (
        (full_report or "").strip()
        + "\n\n"
        + output
    ).strip()

    # -------------------------------------------------
    # Return FINAL result (NO mutation, NO inference)
    # -------------------------------------------------
    return {
        **result,
        "full_report": combined_report
    }

def get_coordinator_output(crew_result):
    if isinstance(crew_result, str):
        return crew_result

    if hasattr(crew_result, "tasks_output") and crew_result.tasks_output:
        return crew_result.tasks_output[-1].raw_output

    raise RuntimeError(
        f"Unsupported CrewAI result format: {type(crew_result)}"
    )

def flatten_legitimate_domains(legit_domains: dict) -> set:
    """
    Flattens LEGITIMATE_DOMAINS into a set of exact domains.
    """
    domains = set()

    for value in legit_domains.values():
        if isinstance(value, list):
            domains.update(value)
        else:
            domains.add(value)

    return domains


def is_exact_legitimate_domain(url: str, legit_domain_set: set) -> bool:
    """
    Checks if the URL hostname exactly matches or is a subdomain
    of a known legitimate domain.
    """
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False

        hostname = hostname.lower()

        for legit_domain in legit_domain_set:
            legit_domain = legit_domain.lower()
            if hostname == legit_domain or hostname.endswith("." + legit_domain):
                return True

        return False
    except Exception:
        return False
