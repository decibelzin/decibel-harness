---
name: Reconnaissance methodology
description: A disciplined recon workflow for a new target — enumerate the attack surface breadth-first, fingerprint every open service, and record concrete exposures before moving on.
subdomain: reconnaissance
when_to_use: At the start of any engagement, or whenever a new host, subnet, or service comes into scope and its attack surface is unknown.
---

# Reconnaissance methodology

Goal: turn an unknown target into a mapped attack surface with recorded, concrete
findings. Work **breadth-first** — enumerate everything shallowly before you go deep
on any one service.

## 1. Port & service discovery

- Run `port_scan` against the target first. It is the native scanner and needs no
  `nmap` on the host. Note **every** open port, not just the famous ones — odd high
  ports (custom services, admin panels, debug endpoints) are often the softest target.
- For anything that looks like a web port, follow up with `http_probe` to capture the
  status, title, server banner, and detected tech.
- For a raw/unknown TCP service (a custom banner, a non-HTTP port), connect with the
  `shell` tool (`bash -c 'exec 3<>/dev/tcp/HOST/PORT; head -c 4096 <&3'` under Git
  Bash, or a short Python socket) to read the banner and probe the protocol. Read
  before you write — many services send a greeting and reset on unexpected input.

## 2. Fingerprint each service

For every open port, capture: service name, product, **version**, and any banner. A
version string is what maps a service to known CVEs — feed it to `cve_by_package` /
`cve_lookup`. Note default-credential candidates (databases, admin panels).

## 3. Web surface

For each web service: fetch the root and a few common paths, read response headers
(`Server`, `X-Powered-By`, cookies, CSP), and note the framework. Use `web_crawl` /
`content_discovery` to find endpoints, and `tls_inspect` on HTTPS ports for cert
details and misconfig.

## 4. Record as you go — do NOT wait for the end

The single most common recon mistake is to enumerate everything and record nothing.
The moment you confirm a concrete exposure — an unauthenticated service, an exposed
database, a leaked version, a debug endpoint — call `record_finding` immediately with
a severity, the target (`host:port` or URL), a MITRE technique, and the evidence
(the actual request/response bytes). A finding you did not record does not exist to
the rest of the engagement.

## Priorities for what to hand off next

Rank discovered services for the exploitation phase by: (1) custom/business-logic
services (least hardened), (2) databases and auth services with default-cred
potential, (3) web apps with a named framework/version, (4) exposed management
protocols (SMB, RDP, RPC). Hand the concrete list — not a vague summary — to the
next phase.
