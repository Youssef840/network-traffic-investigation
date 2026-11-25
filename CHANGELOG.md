# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/), versioning: [SemVer](https://semver.org/).

## [1.1.0] - 2026-11-25

### Added
- Interactive, self-contained **HTML dashboard** (`<case>_report.html`): risk gauge, KPIs, filterable/sortable findings, IOC table with one-click copy, TLS volume per server IP.
- **STIX 2.1 bundle** export (`<case>_stix.json`) for MISP / OpenCTI / TIP import, with deterministic object IDs.
- Installable package (`pyproject.toml`) with an `nti` console command and `python -m nti`.
- Test suite (pytest, 32 tests, ~94% coverage) including an end-to-end check that every planted scenario is detected.
- Dockerfile (non-root), Makefile, pre-commit hooks, ruff config.
- GitHub community files: contributing guide, security policy, issue/PR templates, Dependabot.

### Changed
- CLI moved into `nti/cli.py`; `analyze.py` remains as a backward-compatible shim.
- CI now runs lint + tests + coverage on Linux/Windows/macOS and builds the Docker image.
- New flags: `--no-html`, `--no-stix`, `--version`.

## [1.0.0] - 2026-11-15

### Added
- Initial release: Scapy-based PCAP parser, DNS / TLS (SNI + JA3) / anomaly detectors, IOC extraction, executive + tactical PDF report, CSV/JSON exports, synthetic incident PCAP generator.
