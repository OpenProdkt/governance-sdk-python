"""Process entry points for the decision-point example.

Modes:
  sdk              SDK-protected HTTP (PORT) and gRPC (GRPC_PORT) in one process, shared store and webhook.
  upstream-http    Proxy-only REST upstream (PORT). No SDK.
  upstream-grpc    Proxy-only gRPC upstream (GRPC_PORT). No SDK.
  healthcheck URL  Exit 0 when an http(s) URL returns 200, or when grpc://host:port is ready.
"""

from __future__ import annotations

import os
import sys
import urllib.request
from collections.abc import Callable
from typing import cast

from .app import GovernanceAPI, RefundService, RefundStore, Settings, create_app
from .grpc_refunds import create_embedded_grpc_server, create_upstream_grpc_server

HEALTH_TIMEOUT_SECONDS = 3


def _port(name: str, default: int) -> int:
    return int(os.getenv(name, str(default)))


def run_sdk() -> None:
    import uvicorn
    from openprodkt_governance import GovernanceClient

    settings = Settings.from_environment()
    governance = GovernanceClient(settings.api_base_url, settings.api_key)
    store = RefundStore()
    service = RefundService(governance, store, settings.asset_key)
    grpc_server, _ = create_embedded_grpc_server(
        governance, service, store, settings.asset_key, address=f"0.0.0.0:{_port('GRPC_PORT', 9091)}"
    )
    grpc_server.start()
    try:
        uvicorn.run(create_app(settings, governance, store), host="0.0.0.0", port=_port("PORT", 8000))
    finally:
        grpc_server.stop(grace=5).wait()


def run_upstream_http() -> None:
    import uvicorn

    from .upstream import create_upstream_app

    uvicorn.run(create_upstream_app(), host="0.0.0.0", port=_port("PORT", 8080))


def run_upstream_grpc() -> None:
    # The upstream never calls the SDK, so the governance dependency is intentionally absent.
    store = RefundStore()
    service = RefundService(cast(GovernanceAPI, None), store, "")
    server, _ = create_upstream_grpc_server(service, store, address=f"0.0.0.0:{_port('GRPC_PORT', 9090)}")
    server.start()
    server.wait_for_termination()


def run_healthcheck(target: str) -> int:
    if target.startswith("grpc://"):
        import grpc

        with grpc.insecure_channel(target.removeprefix("grpc://")) as channel:
            try:
                grpc.channel_ready_future(channel).result(timeout=HEALTH_TIMEOUT_SECONDS)
            except grpc.FutureTimeoutError:
                return 1
        return 0
    try:
        with urllib.request.urlopen(target, timeout=HEALTH_TIMEOUT_SECONDS) as response:
            return 0 if response.status == 200 else 1
    except OSError:
        return 1


MODES: dict[str, Callable[[], None]] = {
    "sdk": run_sdk,
    "upstream-http": run_upstream_http,
    "upstream-grpc": run_upstream_grpc,
}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) == 2 and args[0] == "healthcheck":
        return run_healthcheck(args[1])
    if len(args) == 1 and args[0] in MODES:
        MODES[args[0]]()
        return 0
    print("usage: serve {sdk,upstream-http,upstream-grpc} | serve healthcheck TARGET", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
