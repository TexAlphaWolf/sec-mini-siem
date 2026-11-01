# Writing rules

A rule is one YAML file in `rules/`. Validate your rules at any time with:

```bash
minisiem rules check            # uses $MINISIEM_RULES_DIR, default ./rules
minisiem rules check my-rules/  # or point at a directory
```

## Minimal rule

```yaml
id: ssh-root-login            # unique; lowercase letters, digits, - and _
title: Successful SSH login as root
severity: medium              # low | medium | high | critical
match:
  event_type: ssh_accepted
  username: root
```

All keys under `match` must be true (AND). Give a list to accept any of several values (OR).

## Optional keys

```yaml
description: Text shown to the analyst.
tags: [attack.initial_access, attack.t1078]    # MITRE ATT&CK, as in Sigma
threshold:
  count: 5          # fire after this many matching events ...
  window: 60s       # ... inside this window (s, m, h or d)
  group_by: src_ip  # ... counted separately per value of this field
  distinct: username  # optional: count different values of this field, not events
```

### Counting distinct values

With `distinct`, the threshold counts how many *different* values of a field were seen, instead of
how many events. This tells apart attacks that look alike in a plain count:

```yaml
# Password spraying: many accounts from one IP (a brute force hammers one account instead)
threshold: {count: 5, window: 10m, group_by: src_ip, distinct: username}
```

The alert lists some of the values in its details. `distinct` and `group_by` must be different
fields, and events that lack the `distinct` field are ignored.

### Keeping noisy rules quiet

A rule without `threshold` raises one alert for every matching event. For anything an automated
tool can trigger hundreds of times (scanners, injection tools), use `count: 1`: it alerts on the
first match, then stays silent for that group until the window has passed.

```yaml
threshold: {count: 1, window: 10m, group_by: src_ip}   # one alert per IP per 10 minutes
```

## Modifiers

Add a modifier after the field name with `|`:

| Modifier | Meaning | Example |
|----------|---------|---------|
| *(none)* | equals | `username: root` |
| `contains` | substring | `path_decoded\|contains: /.env` |
| `startswith` | prefix | `path\|startswith: /admin` |
| `endswith` | suffix | `path\|endswith: .php` |
| `re` | regular expression | `path\|re: '^/api/v[0-9]+/'` |
| `gte` / `lte` | number comparison | `status\|gte: 500` |

Text comparisons ignore case.

## Fields you can match on

Every event has `source`, `event_type`, `host`, `src_ip`, `username`. Extra fields depend on the
log source.

**`auth` source**

| `event_type` | Extra fields |
|--------------|--------------|
| `ssh_failed_password` | `auth_method`, `invalid_user`, `port`, `program`, `pid` |
| `ssh_invalid_user` | `port`, `program`, `pid` |
| `ssh_accepted` | `auth_method`, `port`, `program`, `pid` |
| `sudo_failure` | `attempts`, `target_user`, `command` |
| `sudo_command` | `target_user`, `command`, `pwd` |

**`nginx` source** (`event_type: http_request`)

`http_method`, `path`, `path_decoded`, `protocol`, `status`, `bytes`, `referrer`, `user_agent`

Prefer `path_decoded` for attack patterns: it is URL-decoded once, so `union%20select` becomes
`union select`.

## Exporting to Sigma

```bash
minisiem rules export -o sigma-rules.yml
```

Every rule becomes a Sigma detection rule; rules with a threshold also get a Sigma v2
correlation rule (`event_count`, or `value_count` when the threshold uses `distinct`). Two
caveats: the field names are Mini-SIEM's own (`src_ip`, `username`, ...), so a Sigma backend needs
a field mapping for your log store; and the one-alert-per-window silencing has no Sigma
equivalent, so `count: 1` rules are exported as plain detections.

## Adding support for a new log format

1. Create `src/minisiem/parsers/<name>.py` with a function that takes one line and returns an
   `Event` (or `None` if it is not understood).
2. Register it in `PARSERS` in `src/minisiem/parsers/__init__.py`.
3. Add tests with a few real, anonymised lines.

Sources are then available as `minisiem ingest <name> ...` and `POST /ingest/<name>`.
