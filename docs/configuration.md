# Configuration

Everything is set with environment variables. With Docker Compose, put them in `.env` (start from
`.env.example`); outside Docker, export them or put them in your service definition.

## Core

| Variable | Default | Meaning |
|----------|---------|---------|
| `DATABASE_URL` | local SQLite file | SQLAlchemy URL. Overrides the `POSTGRES_*` variables |
| `POSTGRES_HOST`, `_PORT`, `_USER`, `_PASSWORD`, `_DB` | - | PostgreSQL connection in parts; the password may contain any character |
| `MINISIEM_RULES_DIR` | `rules` | Directory with the rule files |
| `MINISIEM_LOG_TZ` | `UTC` | Time zone of syslog timestamps (they carry none) |
| `MINISIEM_API_TOKEN` | off | Bearer token required by `POST /ingest` |
| `MINISIEM_READ_TOKEN` | off | Bearer token required by `GET /api/*` (the dashboard asks for it) |
| `MINISIEM_RETENTION_DAYS` | `0` (keep all) | Delete events and alerts older than this |
| `MINISIEM_PORT` | `8000` | Host port in `docker-compose.yml` |

## Notifications

Alerts can be sent to Telegram, to a webhook and by email. Every channel is optional and you can
use several at once. After setting them, check that they work:

```bash
docker compose exec app minisiem notify-test      # or: minisiem notify-test
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `MINISIEM_NOTIFY_MIN_SEVERITY` | `high` | Send alerts of at least this severity: `low`, `medium`, `high`, `critical` |
| `MINISIEM_NOTIFY_MAX_AGE_MINUTES` | `60` | Ignore alerts whose events are older than this (`0` = no limit) |
| `MINISIEM_NOTIFY_MAX_PER_MINUTE` | `20` | Rate limit; the rest is reported in one summary message |

**Only recent alerts are sent.** Importing an old log file creates alerts too, but they are
history: messages are limited to alerts from the last hour (see the age setting) and to the rate
limit above, so an import cannot flood your phone. `minisiem ingest` of a plain file never sends
messages; `serve` and `ingest --follow` do.

### Telegram

1. Talk to [@BotFather](https://t.me/BotFather), run `/newbot`, and copy the token.
2. Send any message to your new bot, then open
   `https://api.telegram.org/bot<token>/getUpdates` and read `chat.id`.

| Variable | Meaning |
|----------|---------|
| `MINISIEM_TELEGRAM_TOKEN` | Bot token |
| `MINISIEM_TELEGRAM_CHAT_ID` | Chat to send to |

### Webhook

| Variable | Default | Meaning |
|----------|---------|---------|
| `MINISIEM_WEBHOOK_URL` | - | `http://` or `https://` URL that receives a `POST` |
| `MINISIEM_WEBHOOK_TOKEN` | - | Sent as `Authorization: Bearer <token>` |
| `MINISIEM_WEBHOOK_FORMAT` | `json` | `json` or `discord` |

The `json` body is `{"text": "...", "alert": {...}}`. The `text` field is what Slack, Mattermost
and Rocket.Chat incoming webhooks display; `alert` holds the full alert for your own tools. With
`discord` the body is `{"content": "..."}`.

### Email

| Variable | Default | Meaning |
|----------|---------|---------|
| `MINISIEM_SMTP_HOST` | - | Mail server |
| `MINISIEM_SMTP_PORT` | `587` | Port |
| `MINISIEM_SMTP_SECURITY` | `starttls` | `starttls`, `ssl` or `none` (only for a trusted local relay) |
| `MINISIEM_SMTP_USER`, `_PASSWORD` | - | Login, if the server needs one |
| `MINISIEM_SMTP_FROM` | - | Sender address |
| `MINISIEM_SMTP_TO` | - | Recipients, separated by commas |

### How messages are protected

Alert text is built from log lines that an attacker wrote, so messages are plain text only:
control characters are removed and long values are cut. Telegram messages use no markup mode, and
nothing from a log is ever placed in an email header. Redirects from a webhook are not followed,
and failed deliveries are logged without the URL or any credential.

## GeoIP

Alerts and the "top sources" list show the country of public source addresses when a GeoIP
database is configured. The lookup is local: addresses are never sent to a third party.

1. Create a free account at [MaxMind](https://www.maxmind.com/en/geolite2/signup) and download
   **GeoLite2 City** (or **Country**) in `.mmdb` format. **GeoLite2 ASN** is optional and adds the
   network owner.
2. Put the files in the `geoip/` folder of the project. Git ignores `*.mmdb`: MaxMind's licence
   does not allow redistributing them, so never commit them.
3. Set the paths *inside the container*:

```
MINISIEM_GEOIP_DB=/geoip/GeoLite2-City.mmdb
MINISIEM_GEOIP_ASN_DB=/geoip/GeoLite2-ASN.mmdb
```

| Variable | Meaning |
|----------|---------|
| `MINISIEM_GEOIP_DB` | GeoLite2 City or Country database |
| `MINISIEM_GEOIP_ASN_DB` | GeoLite2 ASN database (optional) |

Private, loopback and documentation addresses (such as the ones in the sample logs) have no
location, so the demo shows none. If a path is wrong, the app refuses to start and says which
setting is at fault.
