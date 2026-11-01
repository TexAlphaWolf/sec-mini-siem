# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [0.1.0] - 2026-11-01

### Added
- Parsers for Linux auth logs (sshd, sudo) and the nginx/Apache combined access log format
- Sigma-inspired YAML rule engine with field modifiers (`contains`, `startswith`, `endswith`,
  `re`, `gte`, `lte`) and sliding-window thresholds
- Ten detection rules, each tagged with its MITRE ATT&CK technique
- FastAPI service with a JSON API (alerts, events, stats) and an ingest endpoint with an
  optional bearer token
- Dependency-free dashboard that never renders log data as HTML
- Command line interface: `serve`, `ingest` (with `--follow`) and `rules check`
- Docker Compose setup with PostgreSQL and a configurable host port
- Anonymised sample logs, a 48-test suite and CI on GitHub Actions
