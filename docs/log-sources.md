# Log sources

Four sources are built in. Choose one with `minisiem ingest <source> <file>` or
`POST /ingest/<source>`.

| Source | What it reads | Rules that use it |
|--------|---------------|-------------------|
| `auth` | `/var/log/auth.log` or `/var/log/secure` (sshd, sudo) | `ssh-*`, `sudo-*` |
| `nginx` | nginx / Apache access logs in the *combined* format | `web-*` |
| `journald` | `journalctl -o json` (sshd, sudo) | the same `ssh-*` and `sudo-*` rules |
| `windows` | Windows Security and System events as JSON lines | `win-*` |

Rules match on `event_type`, not on the source, so a rule written for `auth` works unchanged on
`journald`.

## auth

```bash
minisiem ingest auth /var/log/auth.log --year 2026
```

Syslog timestamps carry no year or time zone: pass `--year` for old files and set
`MINISIEM_LOG_TZ` (for example `Europe/Rome`) to the time zone of the machine that wrote them.

## nginx

```bash
minisiem ingest nginx /var/log/nginx/access.log
```

The default `combined` log format of nginx and Apache. Request paths are URL-decoded once into
`path_decoded` for matching.

## journald

Hosts that use systemd often have no `auth.log`; the journal holds the same messages.

```bash
journalctl -o json --since yesterday | minisiem ingest journald -
journalctl -o json -f -u ssh | minisiem ingest journald -    # keep sending
```

The time comes from `__REALTIME_TIMESTAMP` (microseconds, UTC), so no time zone setting is needed.

## windows

Windows events are exported as one JSON object per line. Run this in an **administrator**
PowerShell (reading the Security log needs it), then copy the file to the machine that runs
Mini-SIEM:

```powershell
$ids = 4624,4625,4672,4698,4720,4728,4732,4756,1102
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = (Get-Date).AddDays(-1) } |
  ForEach-Object {
    $xml  = [xml]$_.ToXml()
    $data = [ordered]@{}
    foreach ($n in $xml.Event.EventData.Data) { if ($n.Name) { $data[$n.Name] = [string]$n.'#text' } }
    [pscustomobject]@{
      TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o')
      EventID     = $_.Id
      Computer    = $_.MachineName
      Channel     = $_.LogName
      Data        = $data
    } | ConvertTo-Json -Compress -Depth 4
  } | Set-Content -Encoding utf8 windows-security.jsonl
```

Services and cleared logs live in the System log: run the same command with
`LogName = 'System'`, `$ids = 7045,104` and `windows-system.jsonl` as the output file. Then:

```bash
minisiem ingest windows windows-security.jsonl
minisiem ingest windows windows-system.jsonl
```

**Events understood**

| Event ID | Log | `event_type` | Meaning |
|----------|-----|--------------|---------|
| 4624 | Security | `win_logon_success` | successful logon (`logon_type`: 2 console, 3 network, 10 Remote Desktop) |
| 4625 | Security | `win_logon_failed` | failed logon |
| 4672 | Security | `win_privileged_logon` | special privileges assigned to a new logon |
| 4698 | Security | `win_scheduled_task_created` | scheduled task created |
| 4720 | Security | `win_user_created` | user account created |
| 4728 / 4732 / 4756 | Security | `win_group_member_added` | member added to a global / local / universal group |
| 1102 / 104 | Security / System | `win_audit_log_cleared` | an event log was cleared |
| 7045 | System | `win_service_installed` | service installed |

Other events are skipped, so you can export more than you need. For the "cleared" events Windows
does not put the user in the usual place, so `username` is empty for them.

**Winlogbeat.** If you already ship events with Winlogbeat, write them to a file with its `file`
output and ingest that: the `winlog.*` layout is understood too.

**Good to know**

- Failed logons are grouped by `IpAddress`. Logons at the console have none, so they never reach
  an IP-based rule.
- Group names are matched in English, Italian, French and German in `win-admin-group-change`;
  extend the list in the rule for other languages.
- Everything in these logs, such as account names and file paths, is chosen by whoever caused the
  event. It is stored as text and shown as text; it is never interpreted.

## Adding another source

See "Adding support for a new log format" in [writing-rules.md](writing-rules.md).
