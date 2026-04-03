# Security Policy

## Supported Versions

Only the latest `MAJOR.MINOR` version is currently supported for security updates.

| Version | Supported          |
| ------- | ------------------ |
| v0.4.x  | :white_check_mark: |
| < v0.4.x| :x:                |

## Reporting a Vulnerability

We take the security of this project seriously. If you believe you've found a vulnerability, please do NOT create a public issue.

Instead, please send an email to **admin@svrnsys.com** or open a private security advisory on GitHub if available.

### What to include:
- A clear description of the vulnerability.
- Steps to reproduce (proof of concept).
- For IP-related bypasses, provide the problematic IP representation.

## Mitigation Log

### CVE-2024-29415 (Incomplete IP Classification)
Following reports of widespread SSRF bypasses in common IP libraries (like `ip`), Shield has implemented its own hardened IP parsing logic in `src/utils/geoip.js`. This logic robustly handles obfuscation techniques including:
- Octal/Hex representations (`0177...`, `0x7f...`)
- Short IPv4 formats (`127.1`, `10.1`)
- Integer notation (`2130706433`)
- IPv4-mapped IPv6 obfuscation (`::ffff:127.0.0.1`)

Tests for these mitigations can be found in `test/geoip_security.test.js`.
