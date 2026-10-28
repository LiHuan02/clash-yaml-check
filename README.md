# clash-yaml-check

A small, dependency-light (PyYAML only) semantic checker for Clash / Mihomo
YAML subscription files.

A YAML syntax check only tells you the file parses. It will happily pass a
config that is broken at runtime. This tool catches the semantic mistakes
that actually break a subscription:

- `rule-providers` whose `type` is not `http` or `file` -- a provider with
  a proxy-protocol value such as `socks5` can never download its rule set
  (the classic damage from a careless global find-and-replace over a config
  that mixes proxy nodes and rule providers);
- `proxy-groups` and `rules` referencing a proxy, group, or rule-provider
  that does not exist (typos, renames, stale entries);
- duplicate proxy / group names, proxies missing `server` / `port`, and
  out-of-range ports;
- `RULE-SET` rules naming an undefined provider, and rule policies pointing
  at unknown targets.

## Usage

```sh
pip install pyyaml
python3 clash_check.py config.yaml
```

Exit status is `0` when no errors are found, `1` otherwise. Warnings (such
as a group sharing a name with a proxy) never change the exit status.

Check your own understanding first, before trusting the tool on a live
config:

```sh
python3 clash_check.py --self-test
# self-test OK: good fixture clean, bad fixture raised 5 errors
```

## Example

```
$ python3 clash_check.py broken.yaml
error: broken.yaml: proxy 'HK-1': missing 'port'
error: broken.yaml: duplicate proxy name: 'HK-1'
error: broken.yaml: proxy-group 'PROXY': unknown proxy/group target 'Ghost-Node'
error: broken.yaml: rule-provider 'ads': type must be 'http' or 'file', got 'socks5' (rule sets cannot download otherwise)
error: broken.yaml: rule 'RULE-SET,missing-provider,REJECT': unknown rule-provider 'missing-provider'
broken.yaml: FAILED (5 error(s))
```

## Scope notes

- `rule-providers` of type `file` are accepted: a local rule file needs no
  `url`, only a `path`.
- Built-in targets `DIRECT`, `REJECT`, `REJECT-DROP`, and `PASS` are always
  valid rule policies and group members.
- The tool never rewrites your config and never touches the network; it
  only reads the files you pass on the command line.

## License

MIT. See `LICENSE`.
