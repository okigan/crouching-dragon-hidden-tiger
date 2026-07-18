"""Versioned policy storage: load / save / apply-patch / diff / rollback.

Policies live as YAML on disk; in-memory history enables rollback. Applying a
patch always produces a new immutable-ish snapshot (via Policy.copy) so prior
versions stay intact — important for the loop's no-progress and audit needs.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import Policy, PolicyPatch


class PolicyError(Exception):
    pass


class PolicyStore:
    def __init__(self, policy: Policy):
        self._history: list[Policy] = [policy.copy()]

    # --- construction -----------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "PolicyStore":
        data = yaml.safe_load(Path(path).read_text())
        if not isinstance(data, dict):
            raise PolicyError(f"policy file {path} is not a mapping")
        return cls(Policy.from_dict(data))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(
            yaml.safe_dump(self.current.to_dict(), sort_keys=False)
        )

    # --- access -----------------------------------------------------------
    @property
    def current(self) -> Policy:
        return self._history[-1]

    @property
    def version_count(self) -> int:
        return len(self._history)

    # --- mutation ---------------------------------------------------------
    def apply(self, patch: PolicyPatch) -> Policy:
        """Apply a validated patch, producing (and returning) a new version."""
        if not patch.is_valid(self.current):
            raise PolicyError("refusing to apply invalid patch")
        new = self.current.copy()
        for op in patch.ops:
            _apply_op(new, op)
        new.version = self.current.version + 1
        self._history.append(new)
        return new

    def rollback(self) -> Policy:
        if len(self._history) == 1:
            raise PolicyError("nothing to roll back")
        self._history.pop()
        return self.current

    # --- diff -------------------------------------------------------------
    def diff(self, older: Policy, newer: Policy) -> dict[str, Any]:
        out: dict[str, Any] = {}
        a, b = older.to_dict(), newer.to_dict()
        for section in a:
            if a[section] != b[section]:
                out[section] = {"before": a[section], "after": b[section]}
        return out


def _apply_op(policy: Policy, op: dict[str, Any]) -> None:
    kind = op["op"]
    path = op.get("path", "")
    value = op.get("value")
    section, _, key = path.partition(".")

    if kind in ("allow_add", "tool_allow"):
        lst = getattr(policy, section)[key]
        if value not in lst:
            lst.append(value)
    elif kind in ("allow_remove", "tool_remove"):
        lst = getattr(policy, section)[key]
        if value in lst:
            lst.remove(value)
    elif kind == "tool_deny":
        deny = policy.tools["deny"]
        if value not in deny:
            deny.append(value)
        # denying a tool also removes it from allow
        if value in policy.tools["allow"]:
            policy.tools["allow"].remove(value)
    elif kind == "set_default":
        getattr(policy, section)[key] = value
    elif kind == "set_flag":
        getattr(policy, section)[key] = value
    else:
        raise PolicyError(f"unknown patch op: {kind}")
