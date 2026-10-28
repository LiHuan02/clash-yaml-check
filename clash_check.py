#!/usr/bin/env python3
"""Semantic checker for Clash / Mihomo YAML subscription files.

Syntax checkers only tell you the YAML parses. This tool checks the things
that actually break a subscription at runtime, the class of bug where a
careless bulk edit (e.g. a global sed) silently corrupts the config:

* ``rule-providers`` whose ``type`` is not ``http`` or ``file``
  (a ``socks5``/``vmess``-style value here means the rule set can never
  download -- the exact failure mode this tool was written to catch);
* ``proxy-groups`` and ``rules`` that reference a proxy, group, or
  rule-provider that does not exist (typos, renames, stale entries);
* duplicate proxy / group names, missing ``server``/``port`` fields,
  and out-of-range ports;
* ``RULE-SET`` rules that name an undefined provider.

Usage:
    python3 clash_check.py config.yaml [config2.yaml ...]
    python3 clash_check.py --self-test

Exit status is 0 when no errors are found, 1 otherwise. Warnings never
change the exit status. Only PyYAML is required (``pip install pyyaml``).
"""

import argparse
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("clash_check.py requires PyYAML: pip install pyyaml", file=sys.stderr)
    raise SystemExit(2)

BUILTIN_TARGETS = {"DIRECT", "REJECT", "REJECT-DROP", "PASS"}
PROVIDER_TYPES = {"http", "file"}
PROVIDER_BEHAVIORS = {"domain", "ipcidr", "classical"}


def _is_mapping(value):
    return isinstance(value, dict)


def check_config(cfg, source="<config>"):
    """Return (errors, warnings); each is a list of human-readable strings."""
    errors, warnings = [], []

    def err(msg):
        errors.append(f"{source}: {msg}")

    def warn(msg):
        warnings.append(f"{source}: {msg}")

    if not _is_mapping(cfg):
        return [f"{source}: top level must be a mapping"], warnings

    proxies = cfg.get("proxies") or []
    if not isinstance(proxies, list):
        return [f"{source}: 'proxies' must be a list"], warnings
    proxy_names = set()
    for i, proxy in enumerate(proxies):
        if not _is_mapping(proxy):
            err(f"proxies[{i}] is not a mapping")
            continue
        name = proxy.get("name")
        if not name:
            err(f"proxies[{i}] has no name")
        elif name in proxy_names:
            err(f"duplicate proxy name: {name!r}")
        else:
            proxy_names.add(name)
        if "type" not in proxy:
            err(f"proxy {name!r}: missing 'type'")
        if "server" not in proxy:
            err(f"proxy {name!r}: missing 'server'")
        port = proxy.get("port")
        if port is None:
            err(f"proxy {name!r}: missing 'port'")
        elif not isinstance(port, int) or not 1 <= port <= 65535:
            err(f"proxy {name!r}: invalid port {port!r}")

    groups = cfg.get("proxy-groups") or []
    if not isinstance(groups, list):
        return errors + [f"{source}: 'proxy-groups' must be a list"], warnings
    group_names = set()
    for group in groups:
        if not _is_mapping(group):
            err("proxy-groups entry is not a mapping")
            continue
        name = group.get("name")
        if not name:
            err("proxy-groups entry has no name")
            continue
        if name in group_names:
            err(f"duplicate proxy-group name: {name!r}")
        group_names.add(name)
        if name in proxy_names:
            warn(f"proxy-group {name!r} shares a name with a proxy")

    known_targets = proxy_names | group_names | BUILTIN_TARGETS

    def check_target(ref, where):
        if ref not in known_targets:
            err(f"{where}: unknown proxy/group target {ref!r}")

    for group in groups:
        if not _is_mapping(group):
            continue
        for ref in group.get("proxies") or []:
            check_target(ref, f"proxy-group {group.get('name')!r}")

    providers = cfg.get("rule-providers") or {}
    if not _is_mapping(providers):
        return errors + [f"{source}: 'rule-providers' must be a mapping"], warnings
    for name, provider in providers.items():
        if not _is_mapping(provider):
            err(f"rule-provider {name!r} is not a mapping")
            continue
        ptype = provider.get("type")
        if ptype not in PROVIDER_TYPES:
            err(
                f"rule-provider {name!r}: type must be 'http' or 'file', "
                f"got {ptype!r} (rule sets cannot download otherwise)"
            )
        if ptype == "http" and not provider.get("url"):
            err(f"rule-provider {name!r}: type 'http' requires 'url'")
        if not provider.get("path"):
            err(f"rule-provider {name!r}: missing 'path'")
        behavior = provider.get("behavior")
        if behavior is not None and behavior not in PROVIDER_BEHAVIORS:
            err(f"rule-provider {name!r}: unknown behavior {behavior!r}")
        interval = provider.get("interval")
        if interval is not None and (
            not isinstance(interval, int) or interval <= 0
        ):
            err(f"rule-provider {name!r}: 'interval' must be a positive integer")

    rules = cfg.get("rules") or []
    if not isinstance(rules, list):
        return errors + [f"{source}: 'rules' must be a list"], warnings
    for rule in rules:
        if not isinstance(rule, str):
            err(f"rule {rule!r} is not a string")
            continue
        parts = [p.strip() for p in rule.split(",")]
        if len(parts) < 2:
            err(f"rule {rule!r}: too few fields")
            continue
        if parts[0] == "RULE-SET" and parts[1] not in providers:
            err(f"rule {rule!r}: unknown rule-provider {parts[1]!r}")
        if len(parts) >= 3 and parts[0] != "RULE-SET":
            check_target(parts[-1], f"rule {rule!r}")
        elif len(parts) >= 3:  # RULE-SET: policy is the last field
            check_target(parts[-1], f"rule {rule!r}")

    return errors, warnings


GOOD = """
proxies:
  - {name: "HK-1", type: ss, server: example.com, port: 8388, cipher: aes-256-gcm, password: x}
  - {name: "US-1", type: vmess, server: example.org, port: 443, uuid: y, alterId: 0, cipher: auto}
proxy-groups:
  - {name: "PROXY", type: select, proxies: ["HK-1", "US-1", "DIRECT"]}
  - {name: "Auto", type: url-test, url: "http://www.gstatic.com/generate_204", interval: 300, proxies: ["HK-1"]}
rule-providers:
  ads:
    type: http
    behavior: domain
    url: "https://example.com/ads.yaml"
    path: ./rules/ads.yaml
    interval: 86400
rules:
  - RULE-SET,ads,REJECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY
"""

BAD = """
proxies:
  - {name: "HK-1", type: ss, server: example.com, cipher: aes-256-gcm, password: x}
  - {name: "HK-1", type: ss, server: example.com, port: 8388, cipher: aes-256-gcm, password: x}
proxy-groups:
  - {name: "PROXY", type: select, proxies: ["HK-1", "Ghost-Node", "DIRECT"]}
rule-providers:
  ads:
    type: socks5
    behavior: domain
    url: "https://example.com/ads.yaml"
    path: ./rules/ads.yaml
    interval: 86400
rules:
  - RULE-SET,missing-provider,REJECT
  - MATCH,PROXY
"""


def self_test():
    """Run the built-in good/bad fixtures; exit non-zero on mismatch."""
    good_errs, _ = check_config(yaml.safe_load(GOOD), source="good")
    bad_errs, _ = check_config(yaml.safe_load(BAD), source="bad")
    problems = []
    if good_errs:
        problems.append(f"good fixture should be clean, got: {good_errs}")
    expected = [
        "missing 'port'",
        "duplicate proxy name",
        "unknown proxy/group target 'Ghost-Node'",
        "type must be 'http' or 'file'",
        "unknown rule-provider 'missing-provider'",
    ]
    for needle in expected:
        if not any(needle in e for e in bad_errs):
            problems.append(f"bad fixture missing expected error: {needle}")
    if problems:
        print("SELF-TEST FAILED")
        for problem in problems:
            print(f"  - {problem}")
        print("bad fixture errors were:")
        for error in bad_errs:
            print(f"  - {error}")
        return 1
    print(f"self-test OK: good fixture clean, bad fixture raised {len(bad_errs)} errors")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Semantic checker for Clash / Mihomo YAML configs."
    )
    parser.add_argument("configs", nargs="*", help="YAML config files to check")
    parser.add_argument("--self-test", action="store_true",
                        help="run built-in fixtures and exit")
    args = parser.parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.configs:
        parser.error("give at least one config file (or --self-test)")
    total_errors = 0
    for path in args.configs:
        try:
            with open(path, encoding="utf-8") as handle:
                cfg = yaml.safe_load(handle)
        except OSError as exc:
            print(f"{path}: cannot read file: {exc}")
            total_errors += 1
            continue
        except yaml.YAMLError as exc:
            print(f"{path}: YAML parse error: {exc}")
            total_errors += 1
            continue
        errors, warnings = check_config(cfg, source=path)
        for warning in warnings:
            print(f"warning: {warning}")
        for error in errors:
            print(f"error: {error}")
        if errors:
            print(f"{path}: FAILED ({len(errors)} error(s))")
        else:
            print(f"{path}: OK")
        total_errors += len(errors)
    return 1 if total_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
