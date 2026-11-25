# Contributing

Thanks for helping improve NTI!

## Development setup

```bash
git clone https://github.com/Youssef840/network-traffic-investigation.git
cd network-traffic-investigation
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pre-commit install
```

## Workflow

1. Create a branch: `feat/<name>`, `fix/<name>` or `docs/<name>`.
2. Make your change and add or update tests in `tests/`.
3. Run `make lint test` (or `ruff check . && pytest`).
4. Update `CHANGELOG.md` under an *Unreleased* heading.
5. Open a pull request using the template.

## Adding a detector

1. Add a `_xxx_detections()` method to `nti/detectors.py` and call it from `Analyzer.run()`.
2. Put any tunable values in `Thresholds` (`nti/config.py`) so they can be overridden via `--config`.
3. Map the finding to a MITRE ATT&CK technique in `MITRE` (`nti/config.py`).
4. Plant the scenario in `tools/generate_sample_pcap.py` and add a needle to `tests/test_end_to_end.py`.

## Rules

- **Never commit real captures.** They can contain credentials and private traffic. Use the generator.
- Use RFC 5737 documentation IPs and fictitious domains in samples and tests.
- Keep reports offline-safe: no external scripts, fonts or images in the HTML output.
