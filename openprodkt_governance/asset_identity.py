from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class AssetIdentity:
    application: str
    service: str
    environment: str


def generate_asset_key(application: str, service: str, environment: str) -> str:
    components = (
        ("application", application),
        ("service", service),
        ("environment", environment),
    )
    for name, value in components:
        if not isinstance(value, str) or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value) is None:
            raise ValueError(f"{name} must be a lowercase ASCII DNS label (1-63 characters)")
    return ".".join((application, service, environment))