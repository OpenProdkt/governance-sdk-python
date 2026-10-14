from __future__ import annotations

import os
import time

from openprodkt_governance import GovernanceClient


def main() -> None:
    api_base_url = required("E2E_API_BASE_URL")
    api_key = required("E2E_API_KEY")
    owner_email = required("E2E_EMAIL")
    group_name = f"local-decision-point-{int(time.time())}"
    group = GovernanceClient(api_base_url, api_key).create_group(group_name, owner_email)
    print(f"Approver group created: {group['name']}")


def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


if __name__ == "__main__":
    main()