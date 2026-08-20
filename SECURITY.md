# Security and disclosure policy

This repository is an authorized defensive validation lab, not a scanning tool. Do not aim it at third-party WordPress installations.

If you discover a new issue while extending the lab:

1. Preserve the exact Forminator, WordPress, and PHP versions and the source hash.
2. Prove the complete source-to-sink path and reproduce it over HTTP in an isolated lab.
3. Assert a concrete marker-bearing side effect and include a negative control.
4. Remove credentials, customer identifiers, hostnames, and lab-only secrets from any outward-facing report.
5. Coordinate privately with WPMU DEV and the appropriate CNA before public disclosure.

Do not open a public issue containing a new working exploit for an unfixed vulnerability. Use the repository owner's private security-reporting channel instead.
