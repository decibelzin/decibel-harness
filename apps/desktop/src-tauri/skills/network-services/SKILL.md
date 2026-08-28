---
name: Network service exploitation
description: Playbook for the common exposed services — databases (MySQL/MariaDB, Postgres, Redis, Mongo), SMB/RPC, and SSH — covering safe enumeration, default/weak credentials, and known-CVE checks.
subdomain: network-services
when_to_use: When recon found an exposed non-web service — a database, file share, RPC endpoint, or remote-access service — and you need to assess it without destructive actions.
---

# Network service exploitation

Rule for all of these: **enumerate and confirm non-destructively.** Read data, test
access, check versions against CVEs — do not modify, delete, or disrupt the service.

## Databases (MySQL / MariaDB 3306, Postgres 5432, Redis 6379, Mongo 27017)

- Grab the banner/version first (`port_scan` service version, or connect via `shell`).
  Feed the version to `cve_by_package` — DB versions map cleanly to CVEs.
- Test for **unauthenticated / default credentials**: MySQL/MariaDB `root` with empty
  or `root`/`toor`; Redis with **no auth at all** (a bare `PING`/`INFO` that answers is
  critical — unauth Redis is a frequent RCE/data-leak path); Mongo with no auth.
- If you get read access, confirm impact by reading a benign schema/db list — do not
  dump or alter data. Record the access + what it exposes.

## SMB / RPC (139/445, 135)

- Enumerate shares, null-session access, and the SMB dialect/signing posture. Exposed
  writable shares, null-session enumeration, and SMB signing disabled are all findings.
- Map the OS/version for CVE lookup (EternalBlue-class issues on legacy Windows).

## SSH (22)

- Banner → version → `cve_lookup`. Note weak/legacy KEX or ciphers. Test for weak or
  default credentials only if the engagement authorizes credential testing; otherwise
  record the exposure and auth posture.

## Recording

`record_finding` for each: unauth database access, default creds, exposed share,
vulnerable version. Severity by impact — an unauthenticated database or a writable
share is high/critical; a weak cipher is low. Include the exact `host:port` and the
evidence (the command and its output).
