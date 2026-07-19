"""Translate our OpenShell-compatible `Policy` into a *real* NVIDIA OpenShell
`policy.yaml` (the schema the gateway loads with `openshell policy set`).

Mapping (see the real schema in deploy/openshell + NVIDIA/OpenShell examples):
  - our filesystem.read/write -> filesystem_policy.read_only / read_write
  - our network.allow hosts    -> network_policies endpoints (egress allow-list)
  - network.default == "deny"   -> no endpoints => deny-all egress (OpenShell's
    default is deny, so an empty allow-list is a real block)
  - process runs as the unprivileged `sandbox` user

The network dimension is the one we exercise for real enforcement (proven:
allowed host -> 200, everything else -> 403). Tool/process mapping (shell/code
execution) is coarser and left conservative.
"""

from __future__ import annotations

import yaml

from ..models import Policy

# Baseline read-only paths a sandboxed agent needs to run at all. These are the
# static filesystem paths OpenShell locks at sandbox creation (incl. /app for the
# base image), so they must be present for a live `policy set` to be accepted.
_DEFAULT_READ_ONLY = ["/usr", "/lib", "/proc", "/dev/urandom", "/app",
                      "/etc", "/var/log"]
_DEFAULT_READ_WRITE = ["/sandbox", "/tmp", "/dev/null"]


def to_openshell(policy: Policy, curl_path: str = "/usr/bin/curl") -> dict:
    """Return the real OpenShell policy as a dict (dump with `yaml`)."""
    egress_open = policy.network.get("default") == "allow"
    allow_hosts = list(policy.network.get("allow", []))

    network_policies: dict = {}
    if egress_open or allow_hosts:
        # Allow the explicitly-listed hosts (deny-all otherwise). When our policy
        # is permissive we still only allow concrete hosts OpenShell can enforce.
        hosts = allow_hosts or []
        if hosts:
            network_policies["egress_allow"] = {
                "name": "egress-allow-list",
                "endpoints": [
                    {"host": h, "port": 443, "protocol": "rest",
                     "enforcement": "enforce", "access": "read-only"}
                    for h in hosts
                ],
                "binaries": [{"path": curl_path}],
            }

    # OpenShell rejects "/" as a filesystem rule ("path is overly broad") — its
    # schema can't express "read/write everything". A permissive policy that asks
    # for "/" is clamped to the broadest set OpenShell accepts (the defaults +
    # any concrete subpaths); real enforcement here is on the network dimension.
    read = [p for p in policy.filesystem.get("read", []) if p != "/"]
    write = [p for p in policy.filesystem.get("write", []) if p != "/"]
    read_only = sorted(set(_DEFAULT_READ_ONLY) | set(read))
    read_write = sorted(set(_DEFAULT_READ_WRITE) | set(write))

    return {
        "version": 1,
        "filesystem_policy": {
            "include_workdir": True,
            "read_only": read_only,
            "read_write": read_write,
        },
        "landlock": {"compatibility": "best_effort"},
        "process": {"run_as_user": "sandbox", "run_as_group": "sandbox"},
        "network_policies": network_policies,
    }


def to_openshell_yaml(policy: Policy) -> str:
    return yaml.safe_dump(to_openshell(policy), sort_keys=False)
