```
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░                                                                              ░
░    ▄▀▀█▄▄   ▄▀▀▄ ▄▄   ▄▀▀█▄▄▄▄  ▄▀▀▄ ▀▄  ▄▀▀▄ ▄▀▄  ▄▀▀▀▀▄  ▄▀▀▄ ▀▀▄       ░
░   ░ ▄▀   █ █  █   ▄▀ ▐  ▄▀   ▐ █  █ █ █ █  █ ▀  █ █      █ █   ▀▄ ▄▀      ░
░     █▄▄▄▀  ▐  █▄▄▄█    █▄▄▄▄▄  ▐  █  ▀█ ▐  █    █ █      █ ▐     █        ░
░     █   █     █   █    █    ▌     █   █    █    █  ▀▄    ▄▀        █        ░
░    ▄▀▄▄▄▀    ▄▀  ▄▀   ▄▀▄▄▄▄    ▄▀   █    ▄▀   █     ▀▀▀▀         █        ░
░   █    ▐    █   █     █    ▐    █    █    █    █                   ▐        ░
░   ▐         ▐   ▐     ▐         ▐    ▐    ▐    ▐                            ░
░                                                                              ░
░           A D   E N U M E R A T I O N   &   A U D I T   T O O L             ░
░                     python port of Invoke-ADEnum                             ░
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
```

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey?style=for-the-badge)
![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen?style=for-the-badge)
![Version](https://img.shields.io/badge/Version-1.0.0-orange?style=for-the-badge)

**Comprehensive Active Directory enumeration and auditing — from a single Python script.**  
*Authorized security assessments only.*

</div>

---

## Overview

`ad_enum.py` is a Python 3 port of [Leo4j's Invoke-ADEnum](https://github.com/Leo4j/Invoke-ADEnum), rewritten to run natively on Linux, macOS, and Windows without a PowerShell dependency. It enumerates every significant attack surface in an Active Directory environment via LDAP/LDAPS, then produces colour-coded terminal output, a structured JSON dump, and a dark-themed HTML audit report — all in one pass.

Designed for penetration testers and Active Directory security assessors working under **explicit written authorisation**.

---

## Features

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  RECONNAISSANCE                    PRIVILEGE ESCALATION PATHS               │
│  ─────────────────────────────     ─────────────────────────────────────    │
│  ✓ Domain & forest info            ✓ Kerberoastable accounts (SPNs)         │
│  ✓ Domain controllers              ✓ ASREPRoastable accounts                │
│  ✓ Domain trusts                   ✓ Unconstrained delegation               │
│  ✓ AD Sites & subnets              ✓ Constrained delegation                 │
│  ✓ Organisational units            ✓ Resource-based constrained (RBCD)      │
│  ✓ Group Policy Objects            ✓ AdminSDHolder protected accounts        │
│                                    ✓ High-value group memberships           │
│  MISCONFIGURATIONS                                                          │
│  ─────────────────────────────     CREDENTIALS & EXPOSURE                   │
│  ✓ Obsolete/EOL operating systems  ─────────────────────────────────────    │
│  ✓ LAPS deployment gaps            ✓ Password not required (UAC flag)       │
│  ✓ Interesting ACEs / DACLs        ✓ Accounts with probable empty passwords │
│  ✓ User-created computer objects   ✓ Notable descriptions (pass/cred/key)   │
│  ✓ Default password policy         ✓ Enabled accounts never logged on       │
│  ✓ Fine-grained password policies  ✓ LAPS-readable plaintext passwords      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Requirements

```bash
pip install ldap3
```

> `ldap3` is the only runtime dependency. No impacket, no PowerShell, no .NET.

---

## Installation

```bash
git clone https://github.com/yourname/ad-enum
cd ad-enum
pip install ldap3
python ad_enum.py --help
```

---

## Usage

### Authentication modes

```bash
# Plaintext password
python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local -u jdoe -p 'P@ssw0rd'

# Pass-the-hash (NTLM)
python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local -u jdoe \
    --hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# LDAPS (port 636)
python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local -u jdoe -p 'P@ssw0rd' --ldaps

# Through a SOCKS proxy
proxychains python ad_enum.py --dc-ip 172.16.40.2 --domain corp.local -u jdoe -p 'P@ssw0rd'
```

### Full audit (all modules + report)

```bash
python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local -u jdoe -p 'P@ssw0rd' \
    --report --out-dir ./results
```

Running with no module flags automatically executes all modules and saves both a JSON and HTML report.

### Targeted enumeration

```bash
# Only pull high-value attack paths
python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local -u jdoe -p 'P@ssw0rd' \
    --kerberoastable --asreproastable --unconstrained --rbcd --laps

# EOL systems + password policy only
python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local -u jdoe -p 'P@ssw0rd' \
    --obsolete-os --password-policy --fine-grained
```

---

## Modules

| Flag | Description | Risk Level |
|---|---|:---:|
| `--domain-info` | Domain name, SID, machine account quota | ℹ️ |
| `--forest` | Forest functional level, schema info | ℹ️ |
| `--dcs` | Domain controllers, OS, last logon | ℹ️ |
| `--trusts` | Inter-domain/forest trusts, direction, attributes | ⚠️ |
| `--password-policy` | Default domain password policy | ⚠️ |
| `--fine-grained` | Fine-grained PSO policies and targets | ⚠️ |
| `--users` | All user accounts with UAC, last logon, SPNs | ℹ️ |
| `--kerberoastable` | Users with SPNs — TGS-REP cracking candidates | 🔴 |
| `--asreproastable` | Users with pre-auth disabled — AS-REP cracking | 🔴 |
| `--passwd-not-req` | UAC PASSWD_NOTREQD flag set | 🔴 |
| `--empty-passwords` | Accounts with probable null/empty passwords | 🔴 |
| `--never-logged-on` | Enabled accounts with no logon history | ⚠️ |
| `--descriptions` | Objects with credential keywords in descriptions | 🔴 |
| `--adminsdholder` | adminCount=1 protected accounts | ⚠️ |
| `--groups` | All security groups with member counts | ℹ️ |
| `--admin-groups` | Members of Domain/Enterprise/Schema Admins etc. | 🔴 |
| `--computers` | All computer objects, OS, last logon | ℹ️ |
| `--obsolete-os` | EOL operating systems (XP → Server 2012 R2) | 🔴 |
| `--unconstrained` | Non-DC computers/users with unconstrained delegation | 🔴 |
| `--constrained` | Constrained delegation targets and protocols | ⚠️ |
| `--rbcd` | Resource-based constrained delegation | 🔴 |
| `--ous` | Organisational unit structure and GPO links | ℹ️ |
| `--gpos` | All GPOs with GUIDs, SYSVOL paths, timestamps | ⚠️ |
| `--subnets` | AD Sites and subnet objects | ℹ️ |
| `--acls` | Interesting DACLs (GenericAll, WriteDACL, etc.) | 🔴 |
| `--laps` | LAPS coverage gaps and readable plaintext passwords | 🔴 |
| `--user-created` | Computer objects created by non-system principals | ⚠️ |

---

## Output

### Terminal

Colour-coded output with severity highlighting:

```
[*] Bound as CORP\jdoe
============================================================
  Kerberoastable Accounts (SPNs on User Objects)
============================================================
  svc_sql     | AdminCount: 1
    SPN: MSSQLSvc/db01.corp.local:1433
  svc_backup  | AdminCount: 0
    SPN: backup/fileserver01.corp.local

[!] 2 kerberoastable account(s) found — attempt TGS cracking
```

### HTML Report

A dark-themed, single-file HTML report with:
- Summary stat cards (total users, computers, Kerberoastable, EOL systems…)
- One table per module, anchor-navigated
- Collapsible sections, responsive layout
- No external dependencies — works offline

### JSON

Machine-readable structured output of all findings for pipeline integration or custom reporting.

```bash
# Pipe JSON results to jq
cat results/ad_enum_corp.local_20260330.json | jq '.Kerberoastable[] | .Username'
```

---

## EOL Operating System Coverage

The `--obsolete-os` module queries for each EOL OS individually and prints associated CVE context:

| Operating System | EOL Date | Notable Vulnerabilities |
|---|---|---|
| Windows XP | Apr 2014 | MS08-067, MS17-010, EternalBlue |
| Windows Vista | Apr 2017 | MS17-010, EternalBlue |
| Windows 7 | Jan 2020 | MS17-010, ZeroLogon era |
| Windows 8 / 8.1 | Jan 2023 | Multiple post-EOL unpatched RCEs |
| Server 2000 | Jul 2010 | Unauthenticated RCEs |
| Server 2003 | Jul 2015 | MS08-067, no SMBv2 |
| Server 2008 / R2 | Jan 2020 | EternalBlue, BlueKeep (CVE-2019-0708) |
| Server 2012 / R2 | Oct 2023 | Post-EOL unpatched vulnerabilities |

---

## Examples

### Typical internal pentest run

```bash
# 1. Quick scan — highest-yield findings first
python ad_enum.py --dc-ip 10.10.10.1 --domain corp.local -u 'jdoe' -p 'Password1' \
    --kerberoastable --asreproastable --unconstrained --rbcd \
    --laps --obsolete-os --admin-groups

# 2. Full domain audit with report
python ad_enum.py --dc-ip 10.10.10.1 --domain corp.local -u 'jdoe' -p 'Password1' \
    --report --json --out-dir ./corp-audit/
```

### Via proxychains (pivot host)

```bash
proxychains python ad_enum.py --dc-ip 172.16.5.5 --domain internal.corp -u 'svc_account' \
    --hashes :a87f3a337d73085c45f9416be5787d86 --report
```

---

## Companion Tools

This repo includes additional tooling for AD CS (ADCS) abuse:

### `esc4_enable_template.py` — ESC4 Certificate Template Abuse

Publish a disabled certificate template to a CA via `WriteProperty` (ESC4).

```bash
# Check which CAs host a template
python esc4_enable_template.py --dc-ip 10.10.10.1 --domain corp.local \
    -u jdoe -p 'P@ssw0rd' --check --template KeyRecoveryAgent

# Publish the template to a CA
python esc4_enable_template.py --dc-ip 10.10.10.1 --domain corp.local \
    -u jdoe -p 'P@ssw0rd' --template KeyRecoveryAgent --ca 'CORP-CA'

# Restore (remove from CA)
python esc4_enable_template.py --dc-ip 10.10.10.1 --domain corp.local \
    -u jdoe -p 'P@ssw0rd' --template KeyRecoveryAgent --ca 'CORP-CA' --disable
```

---

## Legal Disclaimer

> This toolset is intended **exclusively** for authorised security assessments, penetration tests, and research conducted under **explicit written permission** from the asset owner.
>
> Unauthorised use against systems you do not own or have permission to test is **illegal** and may result in criminal prosecution. The authors accept no liability for misuse.

---

## Credits

- [Leo4j](https://github.com/Leo4j) — original [Invoke-ADEnum](https://github.com/Leo4j/Invoke-ADEnum) PowerShell tool this is ported from
- [PowerView](https://github.com/PowerShellMafia/PowerSploit) — foundational AD enumeration techniques
- [ldap3](https://github.com/cannatag/ldap3) — Python LDAP library

---

<div align="center">
<sub>Built for authorised security professionals. Test responsibly.</sub>
</div>
