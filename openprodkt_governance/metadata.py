from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from math import isfinite
from typing import Any, Dict

try:
    from pydantic import BaseModel as _PydanticBaseModel
except ImportError:
    _PydanticBaseModel = ()

MAX_METADATA_BYTES = 8 * 1024
MAX_STRING_LENGTH = 256
MAX_ATTACHMENT_COUNT = 64

KNOWN_STRING_KEYS = {
    "provider",
    "model",
    "operation",
    "environment",
    "actor",
    "application",
}

ALLOWED_AI_KEYS = {
    "message_count",
    "message_size_bytes",
    "input_tokens",
    "output_token_limit",
    "attachment_count",
    "attachment_size_bytes",
    "tool_count",
    "request_size_bytes",
}

FORBIDDEN_KEYS = {"raw_message_content", "attachment_content"}


def build_provider_metadata(
    provider: str,
    model: str,
    operation: str,
    environment: str,
    actor: str,
    application: str,
    ai: Dict[str, int],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "provider": provider.strip(),
        "model": model.strip(),
        "operation": operation.strip(),
        "environment": environment.strip(),
        "actor": actor.strip(),
        "application": application.strip(),
        "ai": dict(ai),
    }
    return sanitize_metadata(payload)


def build_openai_metadata(model: str, operation: str, environment: str, actor: str, application: str, ai: Dict[str, int]) -> Dict[str, Any]:
    return build_provider_metadata("openai", model, operation, environment, actor, application, ai)


def build_anthropic_metadata(model: str, operation: str, environment: str, actor: str, application: str, ai: Dict[str, int]) -> Dict[str, Any]:
    return build_provider_metadata("anthropic", model, operation, environment, actor, application, ai)


def build_gemini_metadata(model: str, operation: str, environment: str, actor: str, application: str, ai: Dict[str, int]) -> Dict[str, Any]:
    return build_provider_metadata("gemini", model, operation, environment, actor, application, ai)


def build_openai_compatible_metadata(model: str, operation: str, environment: str, actor: str, application: str, ai: Dict[str, int]) -> Dict[str, Any]:
    return build_provider_metadata("openai_compatible", model, operation, environment, actor, application, ai)


def build_local_metadata(model: str, operation: str, environment: str, actor: str, application: str, ai: Dict[str, int]) -> Dict[str, Any]:
    return build_provider_metadata("local", model, operation, environment, actor, application, ai)


def build_generic_api_metadata(model: str, operation: str, environment: str, actor: str, application: str, ai: Dict[str, int]) -> Dict[str, Any]:
    return build_provider_metadata("generic_api", model, operation, environment, actor, application, ai)


def sanitize_metadata(metadata: Any) -> Dict[str, Any]:
    if metadata is None:
        return {}

    metadata = _to_json_compatible(metadata)
    if not isinstance(metadata, dict):
        raise TypeError("metadata must be a mapping, dataclass, or Pydantic model")

    output: Dict[str, Any] = {}
    for key, value in metadata.items():
        k = key.strip()
        if k in output:
            raise ValueError(f"metadata contains duplicate normalized key '{k}'")
        if k in FORBIDDEN_KEYS:
            raise ValueError(f"metadata key '{k}' is forbidden")
        if k == "ai":
            if not isinstance(value, dict):
                raise ValueError("metadata.ai must be an object")
            output[k] = _sanitize_ai(value)
        elif k in KNOWN_STRING_KEYS:
            if not isinstance(value, str):
                raise ValueError(f"metadata.{k} must be a string")
            output[k] = value.strip()[:MAX_STRING_LENGTH]
        else:
            output[k] = _sanitize_value(value)

    encoded = json.dumps(output, allow_nan=False).encode("utf-8")
    if len(encoded) > MAX_METADATA_BYTES:
        raise ValueError(f"metadata exceeds {MAX_METADATA_BYTES} bytes")

    return output


def _to_json_compatible(value: Any, ancestors: set[int] | None = None) -> Any:
    if ancestors is None:
        ancestors = set()
    if is_dataclass(value) and not isinstance(value, type):
        identity = _enter_container(value, ancestors)
        try:
            return {
                field.name: _to_json_compatible(getattr(value, field.name), ancestors)
                for field in fields(value)
            }
        finally:
            ancestors.remove(identity)
    if _PydanticBaseModel and isinstance(value, _PydanticBaseModel):
        identity = _enter_container(value, ancestors)
        try:
            return _to_json_compatible(value.model_dump(mode="json"), ancestors)
        except Exception as error:
            raise ValueError("Pydantic metadata could not be serialized in JSON mode") from error
        finally:
            ancestors.remove(identity)
    if isinstance(value, Mapping):
        identity = _enter_container(value, ancestors)
        try:
            output: Dict[str, Any] = {}
            for key, nested in value.items():
                if not isinstance(key, str):
                    raise TypeError("metadata mapping keys must be strings")
                output[key] = _to_json_compatible(nested, ancestors)
            return output
        finally:
            ancestors.remove(identity)
    if isinstance(value, (list, tuple)):
        identity = _enter_container(value, ancestors)
        try:
            return [_to_json_compatible(item, ancestors) for item in value]
        finally:
            ancestors.remove(identity)
    if value is None or isinstance(value, (bool, str, int)):
        return value
    if isinstance(value, float):
        if not isfinite(value):
            raise ValueError("metadata numbers must be finite")
        return value
    raise TypeError(f"metadata value type {type(value).__name__} is not supported")


def _enter_container(value: Any, ancestors: set[int]) -> int:
    identity = id(value)
    if identity in ancestors:
        raise ValueError("metadata contains a cyclic value")
    ancestors.add(identity)
    return identity


def _sanitize_ai(values: Dict[str, Any]) -> Dict[str, int]:
    output: Dict[str, int] = {}
    for key, value in values.items():
        k = key.strip()
        if k in output:
            raise ValueError(f"metadata.ai contains duplicate normalized key '{k}'")
        if k in FORBIDDEN_KEYS:
            raise ValueError(f"metadata.ai key '{k}' is forbidden")
        if k not in ALLOWED_AI_KEYS:
            raise ValueError(f"metadata.ai key '{k}' is not allowed")
        if not isinstance(value, (int, float)):
            raise ValueError(f"metadata.ai.{k} must be numeric")
        number = int(value)
        if k == "attachment_count" and number > MAX_ATTACHMENT_COUNT:
            raise ValueError(f"metadata.ai.attachment_count exceeds {MAX_ATTACHMENT_COUNT}")
        output[k] = number
    return output


def _sanitize_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, str, int, float)):
        return value
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, dict):
        output: Dict[str, Any] = {}
        for key, nested in value.items():
            normalized_key = key.strip()
            if normalized_key in output:
                raise ValueError(f"metadata contains duplicate normalized key '{normalized_key}'")
            if normalized_key in FORBIDDEN_KEYS:
                raise ValueError(f"metadata key '{normalized_key}' is forbidden")
            output[normalized_key] = _sanitize_value(nested)
        return output
    raise ValueError(f"metadata value type {type(value).__name__} is not supported")
