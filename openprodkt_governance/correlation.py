"""Dependency-free, explicit correlation for canonical PEP requests."""
import json
import re
import unicodedata
from typing import Any, Dict, Literal, TypedDict


class EvaluateAsset(TypedDict, total=False):
    id: str
    key: str
    application: str
    service: str
    environment: str


class HTTPTransport(TypedDict, total=False):
    method: str
    path: str
    host: str
    scheme: str
    route_id: str
    headers: Dict[str, str]


class GRPCTransport(TypedDict, total=False):
    full_method: str
    service: str
    method: str
    rpc_type: str
    route_id: str
    metadata: Dict[str, str]


class MCPTransport(TypedDict, total=False):
    operation: str
    server: str
    tool: str
    request_id: str
    session_id: str


class _TransportRequired(TypedDict):
    kind: Literal["http", "grpc", "mcp"]


class PEPTransportContext(_TransportRequired, total=False):
    payload_digest: str
    http: HTTPTransport
    grpc: GRPCTransport
    mcp: MCPTransport


class _EvaluateRequired(TypedDict):
    version: str
    asset: EvaluateAsset
    operation_id: str
    transport: PEPTransportContext


class _DefinitionObservationRequired(TypedDict):
    digest: str
    canon: Literal["mcp-tool-definition:v1"]


class DefinitionObservation(_DefinitionObservationRequired, total=False):
    """Optional, untrusted evidence of the called MCP tool's definition digest.

    ``digest`` is ``sha256:`` plus 64 lowercase hex characters and ``canon`` must be
    ``mcp-tool-definition:v1``. ``server_version`` is optional (1 to 128 characters, no
    control characters). The encoded object is at most 512 bytes. It carries a digest
    only, never the description or schema, and the SDK never computes it. Omit it when
    the digest is unknown.
    """
    server_version: str


class _VaultRefRequired(TypedDict):
    kind: Literal["input", "output"]
    object_key: str
    version_id: str
    key_ref: str
    ciphertext_digest: str


class VaultRef(_VaultRefRequired):
    """Pointer to an encrypted record the caller wrote to storage it owns.

    It holds no record content and no key material. ``ciphertext_digest`` is ``sha256:``
    plus 64 lowercase hex characters. The server checks the pointer; the SDK only checks
    its shape.
    """


class VaultGap(TypedDict):
    """Says why a record was not written. ``reason`` is one of the VAULT_GAP_* values."""
    reason: str


VAULT_GAP_KEY_SERVICE_UNAVAILABLE = "key_service_unavailable"
VAULT_GAP_STORAGE_UNAVAILABLE = "storage_unavailable"
VAULT_GAP_RECORD_TOO_LARGE = "record_too_large"
VAULT_GAP_WRITE_FAILED = "write_failed"
VAULT_GAP_REASONS = (
    VAULT_GAP_KEY_SERVICE_UNAVAILABLE,
    VAULT_GAP_STORAGE_UNAVAILABLE,
    VAULT_GAP_RECORD_TOO_LARGE,
    VAULT_GAP_WRITE_FAILED,
)

VAULT_KIND_INPUT = "input"
VAULT_KIND_OUTPUT = "output"


class EvaluateRequest(_EvaluateRequired, total=False):
    approval_id: str
    payload_hash: str
    metadata: Dict[str, Any]
    definition_observation: DefinitionObservation
    vault_ref: VaultRef
    vault_gap: VaultGap


class _OutcomeRequired(TypedDict):
    operation_id: str
    status: Literal["succeeded", "failed", "unknown"]
    completed_at: str


class OperationOutcomeRequest(_OutcomeRequired, total=False):
    result_hash: str
    execution_id: str
    attempt: int
    upstream_request_id: str
    vault_ref: VaultRef
    vault_gap: VaultGap


class OperationOutcomeResponse(TypedDict):
    operation_id: str
    status: str
    recorded: bool


def valid_traceparent(value: Any) -> bool:
    if not isinstance(value, str) or not 55 <= len(value) <= 512 or re.search(r"[,\r\n\t ]", value):
        return False
    if not re.match(r"^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}", value):
        return False
    return (value[:2] != "ff" and value[3:35] != "0" * 32 and value[36:52] != "0" * 16
            and (value[:2] != "00" or len(value) == 55)
            and (len(value) == 55 or (value[55] == "-" and len(value) > 56)))


def validate_outcome_correlation(request: OperationOutcomeRequest) -> None:
    if "execution_id" in request and (not isinstance(request["execution_id"], str) or not re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", request["execution_id"])):
        raise ValueError("execution_id must be a lowercase UUIDv7")
    if "attempt" in request and (type(request["attempt"]) is not int or not 1 <= request["attempt"] <= 2147483647):
        raise ValueError("attempt must be an integer between 1 and 2147483647")
    if "upstream_request_id" in request and (not isinstance(request["upstream_request_id"], str) or not re.fullmatch(
            r"[A-Za-z0-9._:-]{1,128}", request["upstream_request_id"])):
        raise ValueError("invalid upstream_request_id")


DEFINITION_OBSERVATION_CANON = "mcp-tool-definition:v1"
_DEFINITION_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_DEFINITION_KEYS = ("digest", "canon", "server_version")


def validate_definition_observation(value: Any) -> Dict[str, str]:
    """Return the wire form of a definition observation, or raise ValueError.

    Only digest, canon and server_version are carried. The size limit (512 bytes) is
    checked on the compact encoding the SDK actually sends (non-ASCII escaped), so a
    request that passes here is within the limit on the wire.
    """
    if not isinstance(value, dict):
        raise ValueError("definition_observation must be an object")
    unknown = sorted(str(key) for key in value if key not in _DEFINITION_KEYS)
    if unknown:
        raise ValueError("definition_observation has unknown members")
    digest = value.get("digest")
    if not isinstance(digest, str) or not _DEFINITION_DIGEST.fullmatch(digest):
        raise ValueError("definition_observation digest must be sha256: followed by 64 lowercase hex characters")
    if value.get("canon") != DEFINITION_OBSERVATION_CANON:
        raise ValueError("definition_observation canon must be " + DEFINITION_OBSERVATION_CANON)
    wire = {"digest": digest, "canon": DEFINITION_OBSERVATION_CANON}
    if "server_version" in value:
        version = value["server_version"]
        if not isinstance(version, str) or not 1 <= len(version) <= 128:
            raise ValueError("definition_observation server_version must be 1 to 128 characters")
        if any(unicodedata.category(char) in ("Cc", "Cs") for char in version):
            raise ValueError("definition_observation server_version must not contain control characters")
        wire["server_version"] = version
    # The server measures the compacted request member, so the size is that of the compact,
    # ASCII-escaped encoding this SDK sends.
    if len(json.dumps(wire, separators=(",", ":")).encode("utf-8")) > 512:
        raise ValueError("definition_observation must be at most 512 bytes")
    return wire


_VAULT_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_VAULT_REF_KEYS = ("kind", "object_key", "version_id", "key_ref", "ciphertext_digest")


def vault_ref_from_pointer(pointer: Any) -> VaultRef:
    """Return the wire form of a vault writer pointer (the same five values).

    The result is checked only for shape when a request is sent.
    """
    return {
        "kind": pointer.kind, "object_key": pointer.object_key, "version_id": pointer.version_id,
        "key_ref": pointer.key_ref, "ciphertext_digest": pointer.ciphertext_digest,
    }


def validate_vault_members(request: Any, kind: str) -> Dict[str, Any]:
    """Return the wire form of the optional vault members of a request, or raise ValueError.

    ``kind`` is the record kind the request may point to: "input" for an evaluate request,
    "output" for an outcome report. Absent (or None) members are omitted. A request never
    carries both a pointer and a gap. Messages never repeat a supplied value.
    """
    ref, gap = request.get("vault_ref"), request.get("vault_gap")
    wire: Dict[str, Any] = {}
    if ref is not None and gap is not None:
        raise ValueError("vault_ref and vault_gap must not both be supplied")
    if ref is not None:
        if not isinstance(ref, dict):
            raise ValueError("vault_ref must be an object")
        if any(key not in _VAULT_REF_KEYS for key in ref):
            raise ValueError("vault_ref has unknown members")
        if ref.get("kind") != kind:
            raise ValueError("vault_ref kind must be " + kind)
        for key in _VAULT_REF_KEYS[1:]:
            if not isinstance(ref.get(key), str) or not ref[key]:
                raise ValueError("vault_ref " + key + " must be a non-empty string")
        if len(ref["key_ref"]) > 256:
            raise ValueError("vault_ref key_ref must be at most 256 characters")
        if not _VAULT_DIGEST.fullmatch(ref["ciphertext_digest"]):
            raise ValueError("vault_ref ciphertext_digest must be sha256: followed by 64 lowercase hex characters")
        wire["vault_ref"] = {key: ref[key] for key in _VAULT_REF_KEYS}
    if gap is not None:
        if not isinstance(gap, dict) or any(key != "reason" for key in gap):
            raise ValueError("vault_gap must be an object with only a reason")
        if gap.get("reason") not in VAULT_GAP_REASONS:
            raise ValueError("vault_gap reason is not supported")
        wire["vault_gap"] = {"reason": gap["reason"]}
    return wire


def validate_evaluation_transport(transport: Dict[str, Any]) -> None:
    if "arguments" in transport.get("mcp", {}):
        raise ValueError("raw MCP arguments must not be sent; use a payload digest")
    for headers in (transport.get("http", {}).get("headers", {}), transport.get("grpc", {}).get("metadata", {})):
        if any(key.lower() in {"authorization", "proxy-authorization", "cookie", "set-cookie"} for key in headers):
            raise ValueError("credentials must not be sent in transport metadata")
