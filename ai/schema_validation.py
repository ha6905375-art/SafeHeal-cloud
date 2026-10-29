"""
Check a model reply against the AI Reasoning output schema (ai/output_schema.json).

Standard library only. Supports the JSON Schema keywords that output_schema.json
uses: type (single or list), properties, required, items, enum, const.

Error messages name the JSON path and the rule that failed. They never echo
values from the reply, so a secret in the model output cannot leak through them.
"""

import json
from pathlib import Path
from typing import Any, Optional

SCHEMA_FILE = Path(__file__).resolve().parent / "output_schema.json"
MAX_ERRORS = 50

_TYPE_CHECKS = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


def load_output_schema(path: Path = SCHEMA_FILE) -> dict:
    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def _type_name(value: Any) -> str:
    for name in ("null", "boolean", "integer", "number", "string", "array", "object"):
        if _TYPE_CHECKS[name](value):
            return name
    return type(value).__name__


def _check(value: Any, schema: dict, path: str, errors: list[str]) -> None:
    if len(errors) >= MAX_ERRORS:
        return

    expected = schema.get("type")
    if expected is not None:
        allowed = expected if isinstance(expected, list) else [expected]
        if not any(_TYPE_CHECKS.get(t, lambda v: False)(value) for t in allowed):
            errors.append(f"{path}: expected {' or '.join(allowed)}, got {_type_name(value)}")
            return  # nested checks would only add noise

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: value is not one of {schema['enum']}")
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: must equal {json.dumps(schema['const'])}")

    if isinstance(value, dict):
        for field in schema.get("required", []):
            if field not in value:
                errors.append(f"{path}: missing required field '{field}'")
        for field, sub_schema in schema.get("properties", {}).items():
            if field in value:
                _check(value[field], sub_schema, f"{path}.{field}", errors)

    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            _check(item, schema["items"], f"{path}[{index}]", errors)


def validate_against_schema(data: Any, schema: Optional[dict] = None) -> list[str]:
    """Return a list of schema violations (empty list = valid)."""
    errors: list[str] = []
    _check(data, schema if schema is not None else load_output_schema(), "$", errors)
    return errors[:MAX_ERRORS]
