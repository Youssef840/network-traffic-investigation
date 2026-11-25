# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | ✅ |
| < 1.1   | ❌ |

## Reporting a vulnerability

Please **do not open a public issue** for security problems (for example a crafted PCAP that crashes the parser or injects content into a report).

Use GitHub's private reporting instead: **Security → Report a vulnerability** on this repository. Include a minimal reproducer (a synthetic PCAP if possible, never a real capture) and the NTI version.

You can expect an acknowledgement within 72 hours and a fix or mitigation plan within 14 days.

## Handling evidence

NTI processes untrusted input. Run it on an analysis workstation, preferably via the provided Docker image (non-root user), and treat generated reports as TLP-marked material.
