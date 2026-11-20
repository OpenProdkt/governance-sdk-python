"""One-shot outcome observation; never execution retries or payload capture."""
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, Optional, TypeVar, TypedDict
from .correlation import OperationOutcomeRequest

T = TypeVar("T")

class GuardOptions(TypedDict, total=False):
    execution_id: str
    attempt: int
    upstream_request_id: str
    traceparent: str


class _GuardVaultRequired(TypedDict):
    writer: Any
    organization_id: str
    input: Any


class GuardVault(_GuardVaultRequired, total=False):
    """Opt-in evidence records written to storage you own, around one guarded call.

    ``writer`` is a ``openprodkt_governance.vault.VaultWriter`` (or any object with the
    same ``write(kind, organization_id, operation_id, n, record)`` method). ``input`` is
    the record to store before the call is evaluated. ``output`` maps the callback result
    to the record to store after the call; returning None skips the write. Both records
    are supplied by you and are sent only to the writer, never to the policy service.
    ``continue_without_vault`` (default False) lets the call proceed, with a gap
    reported, when the input record cannot be written.
    """
    output: Callable[[Any], Any]
    continue_without_vault: bool


class VaultWriteError(Exception):
    """A required evidence record could not be written, so the call did not run.

    ``reason`` is the gap reason class only. The text never carries a record, a key or
    any detail from the underlying failure.
    """

    def __init__(self, reason: str) -> None:
        super().__init__("evidence vault write failed: " + reason)
        self.reason = reason

    def __reduce__(self) -> Any:
        return (type(self), (self.reason,))

@dataclass(frozen=True)
class GuardResult(Generic[T]):
    value: T
    _report: OperationOutcomeRequest = field(repr=False)
    reporting_error: Optional[BaseException] = None

    @property
    def report(self) -> OperationOutcomeRequest:
        """Detached snapshot for an explicit report-only retry, never re-execution."""
        return self._report.copy()
