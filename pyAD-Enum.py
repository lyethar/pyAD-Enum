#!/usr/bin/env python3
"""
ad_enum.py - Python port of Invoke-ADEnum
Active Directory Auditing and Enumeration Tool
Original: https://github.com/Leo4j/Invoke-ADEnum

Requires: ldap3, impacket, dnspython
  pip install ldap3 impacket dnspython

Usage:
  # Anonymous/Null session
  python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local

  # Authenticated (password)
  python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local -u jdoe -p 'P@ssw0rd'

  # Authenticated (NTLM hash)
  python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local -u jdoe --hashes aad3b435:31d6cfe0

  # Full audit with HTML report
  python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local -u jdoe -p 'P@ssw0rd' --report

  # Select modules
  python ad_enum.py --dc-ip 192.168.1.10 --domain corp.local -u jdoe -p 'P@ssw0rd' \
      --users --kerberoastable --asreproastable --groups --computers --acls --gpos \
      --trusts --rbcd --laps --shares --subnets --report
"""

import argparse
import sys
import json
import datetime
import socket
import struct
import re
from base64 import b64encode
from collections import defaultdict
from pathlib import Path

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, SASL, KERBEROS, SUBTREE, ALL_ATTRIBUTES
    from ldap3.core.exceptions import LDAPException
except ImportError:
    print("[-] ldap3 not found. Install with: pip install ldap3")
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# ANSI colours
# ──────────────────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
MAGENTA= "\033[95m"
WHITE  = "\033[97m"


def banner():
    print(f"""{CYAN}{BOLD}
  ___      _   _ _____ _   _ _   _ __  __
 / _ \\    | | | | ____| \\ | | | | |  \\/  |
/ /_\\ \\ __| | | |  _| |  \\| | | | | |\\/| |
|  _  |/ _` | | | |___| |\\  | |_| | |  | |
|_| |_|\\__,_|_| |_____|_| \\_|\\___/|_|  |_|
  Active Directory Enumeration — Python Port
  Original by Leo4j | Port by ad_enum.py
{RESET}""")


def info(msg):    print(f"{CYAN}[*]{RESET} {msg}")
def success(msg): print(f"{GREEN}[+]{RESET} {msg}")
def warn(msg):    print(f"{YELLOW}[!]{RESET} {msg}")
def error(msg):   print(f"{RED}[-]{RESET} {msg}")
def section(msg): print(f"\n{BOLD}{BLUE}{'='*60}{RESET}\n{BOLD}{BLUE}  {msg}{RESET}\n{BOLD}{BLUE}{'='*60}{RESET}")


# ──────────────────────────────────────────────────────────────────────────────
# LDAP helpers
# ──────────────────────────────────────────────────────────────────────────────
def get_base_dn(domain: str) -> str:
    return ",".join(f"DC={part}" for part in domain.split("."))


def connect_ldap(args) -> Connection:
    """Establish an LDAP(S) connection using password or NTLM hash."""
    use_ssl  = args.ldaps
    port     = 636 if use_ssl else 389
    server   = Server(args.dc_ip, port=port, use_ssl=use_ssl, get_info=ALL)

    user = None
    password = None
    auth_method = ldap3.ANONYMOUS

    if args.username:
        domain_user = f"{args.domain}\\{args.username}"
        auth_method = NTLM
        if args.hashes:
            # Build NT hash for pass-the-hash; ldap3 accepts lm:nt or :nt
            lmhash, nthash = (args.hashes.split(":") + [""])[:2]
            password = f"{lmhash}:{nthash}"
        else:
            password = args.password or ""
        user = domain_user

    try:
        conn = Connection(
            server,
            user=user,
            password=password,
            authentication=auth_method,
            auto_bind=True,
        )
        success(f"Bound to {args.dc_ip} as {'anonymous' if not user else user}")
        return conn
    except LDAPException as exc:
        error(f"LDAP bind failed: {exc}")
        sys.exit(1)


def ldap_search(conn, base_dn, search_filter, attributes=None, page_size=500):
    """Paginated LDAP search; returns list of entries."""
    attributes = attributes or [ALL_ATTRIBUTES]
    results    = []
    entry_gen  = conn.extend.standard.paged_search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=attributes,
        paged_size=page_size,
        generator=True,
    )
    for entry in entry_gen:
        if entry.get("type") == "searchResEntry":
            results.append(entry)
    return results


def attr(entry, name, default=""):
    """Safely get an attribute from an ldap3 entry dict."""
    val = entry.get("attributes", {}).get(name, default)
    if isinstance(val, list):
        return val[0] if val else default
    return val if val is not None else default


def attr_list(entry, name):
    val = entry.get("attributes", {}).get(name, [])
    if not isinstance(val, list):
        val = [val] if val else []
    return val


def filetime_to_dt(ft):
    """Convert Windows FILETIME (100ns intervals since 1601) to datetime."""
    if not ft or ft in (0, 9223372036854775807):
        return None
    try:
        ft = int(ft)
        epoch = datetime.datetime(1601, 1, 1)
        return epoch + datetime.timedelta(microseconds=ft // 10)
    except Exception:
        return None


def uac_flags(uac_value):
    """Parse UserAccountControl integer into human-readable flags."""
    UAC = {
        0x0001: "SCRIPT",
        0x0002: "ACCOUNTDISABLE",
        0x0008: "HOMEDIR_REQUIRED",
        0x0010: "LOCKOUT",
        0x0020: "PASSWD_NOTREQD",
        0x0040: "PASSWD_CANT_CHANGE",
        0x0080: "ENCRYPTED_TEXT_PWD_ALLOWED",
        0x0100: "TEMP_DUPLICATE_ACCOUNT",
        0x0200: "NORMAL_ACCOUNT",
        0x0800: "INTERDOMAIN_TRUST_ACCOUNT",
        0x1000: "WORKSTATION_TRUST_ACCOUNT",
        0x2000: "SERVER_TRUST_ACCOUNT",
        0x10000: "DONT_EXPIRE_PASSWORD",
        0x20000: "MNS_LOGON_ACCOUNT",
        0x40000: "SMARTCARD_REQUIRED",
        0x80000: "TRUSTED_FOR_DELEGATION",
        0x100000: "NOT_DELEGATED",
        0x200000: "USE_DES_KEY_ONLY",
        0x400000: "DONT_REQ_PREAUTH",
        0x800000: "PASSWORD_EXPIRED",
        0x1000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
        0x4000000: "PARTIAL_SECRETS_ACCOUNT",
    }
    try:
        val = int(uac_value)
    except (TypeError, ValueError):
        return []
    return [name for bit, name in UAC.items() if val & bit]


# ──────────────────────────────────────────────────────────────────────────────
# ACE / ACL helpers
# ──────────────────────────────────────────────────────────────────────────────

INTERESTING_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
    "WriteProperty", "Self", "ExtendedRight",
    "AllExtendedRights", "ForceChangePassword", "AddMember",
}

EXTENDED_RIGHTS_MAP = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership",
}

ACCESS_MASK_MAP = {
    0x000F01FF: "FullControl",
    0x00020014: "ReadControl",
    0x00020000: "ReadPermissions",
    0x00040000: "WritePermissions",
    0x00080000: "ChangeOwner",
    0x00010000: "Delete",
    0x00000001: "CreateChild",
    0x00000002: "DeleteChild",
    0x00000004: "ListChildren",
    0x00000008: "Self",
    0x00000010: "ReadProperty",
    0x00000020: "WriteProperty",
    0x00000040: "DeleteTree",
    0x00000080: "ListObject",
    0x00000100: "ExtendedRight",
    0x00100000: "Synchronize",
}

HIGH_VALUE_GROUPS = {
    "domain admins", "enterprise admins", "schema admins",
    "administrators", "account operators", "backup operators",
    "print operators", "server operators", "group policy creator owners",
    "dnsdmins", "remote management users", "dnsadmins",
}


# ──────────────────────────────────────────────────────────────────────────────
# Enumeration modules
# ──────────────────────────────────────────────────────────────────────────────

class ADEnum:
    def __init__(self, conn: Connection, args):
        self.conn    = conn
        self.args    = args
        self.base_dn = get_base_dn(args.domain)
        self.report  = {}   # module_name -> list[dict]

    # ── Domain Info ──────────────────────────────────────────────────────────
    def enum_domain(self):
        section("Domain Information")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(objectClass=domain)",
            ["name", "distinguishedName", "objectSid", "whenCreated",
             "ms-DS-MachineAccountQuota", "minPwdLength", "minPwdAge",
             "maxPwdAge", "lockoutThreshold", "lockoutDuration",
             "pwdHistoryLength", "pwdProperties"],
        )
        results = []
        for e in entries:
            row = {
                "Name":             attr(e, "name"),
                "DN":               attr(e, "distinguishedName"),
                "SID":              attr(e, "objectSid"),
                "Created":          str(attr(e, "whenCreated", "")),
                "MachineQuota":     attr(e, "ms-DS-MachineAccountQuota", "N/A"),
                "MinPwdLength":     attr(e, "minPwdLength", "N/A"),
                "PwdHistoryLength": attr(e, "pwdHistoryLength", "N/A"),
                "LockoutThreshold": attr(e, "lockoutThreshold", "N/A"),
            }
            results.append(row)
            print(f"  {BOLD}Domain Name        :{RESET} {row['Name']}")
            print(f"  {BOLD}Distinguished Name  :{RESET} {row['DN']}")
            print(f"  {BOLD}SID                :{RESET} {row['SID']}")
            print(f"  {BOLD}Machine Quota      :{RESET} {row['MachineQuota']}")
            print(f"  {BOLD}Min Password Length:{RESET} {row['MinPwdLength']}")
            print(f"  {BOLD}Lockout Threshold  :{RESET} {row['LockoutThreshold']}")
        self.report["Domain Info"] = results

    # ── Forest / Schema info ─────────────────────────────────────────────────
    def enum_forest(self):
        section("Forest / Schema Information")
        schema_dn = f"CN=Schema,CN=Configuration,{self.base_dn}"
        entries = ldap_search(
            self.conn, f"CN=Configuration,{self.base_dn}",
            "(objectClass=crossRefContainer)",
            ["msDS-Behavior-Version", "distinguishedName"],
        )
        results = []
        for e in entries:
            row = {
                "DN":               attr(e, "distinguishedName"),
                "FunctionalLevel":  attr(e, "msDS-Behavior-Version", "Unknown"),
            }
            results.append(row)
            print(f"  {BOLD}Configuration DN    :{RESET} {row['DN']}")
            print(f"  {BOLD}Forest Functional Level:{RESET} {row['FunctionalLevel']}")
        self.report["Forest Info"] = results

    # ── Domain Controllers ────────────────────────────────────────────────────
    def enum_dcs(self):
        section("Domain Controllers")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            ["name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
             "whenCreated", "lastLogonTimestamp", "distinguishedName",
             "ms-DS-MachineAccountQuota", "userAccountControl"],
        )
        results = []
        for e in entries:
            uac  = uac_flags(attr(e, "userAccountControl", 0))
            last = filetime_to_dt(attr(e, "lastLogonTimestamp"))
            row  = {
                "Name":     attr(e, "name"),
                "FQDN":     attr(e, "dNSHostName"),
                "OS":       attr(e, "operatingSystem"),
                "OSVer":    attr(e, "operatingSystemVersion"),
                "LastLogon":str(last) if last else "Never",
                "DN":       attr(e, "distinguishedName"),
                "UAC":      ", ".join(uac),
            }
            results.append(row)
            success(f"  {row['Name']} | {row['FQDN']} | {row['OS']} {row['OSVer']}")
            print(f"         Last Logon: {row['LastLogon']}")
        if not results:
            warn("  No domain controllers found (check permissions)")
        self.report["Domain Controllers"] = results

    # ── Domain Trusts ─────────────────────────────────────────────────────────
    def enum_trusts(self):
        section("Domain Trusts")
        TRUST_DIRECTION = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}
        TRUST_TYPE      = {1: "Windows NT", 2: "Active Directory", 3: "MIT (Kerberos)", 4: "DCE"}
        TRUST_ATTR      = {
            1: "NON_TRANSITIVE", 2: "UPLEVEL_ONLY", 4: "QUARANTINED",
            8: "FOREST_TRANSITIVE", 16: "CROSS_ORG", 32: "WITHIN_FOREST",
            64: "TREAT_AS_EXTERNAL", 128: "MIT_USES_RC4",
        }
        entries = ldap_search(
            self.conn, self.base_dn,
            "(objectClass=trustedDomain)",
            ["name", "trustDirection", "trustType", "trustAttributes",
             "whenCreated", "distinguishedName"],
        )
        results = []
        for e in entries:
            td  = int(attr(e, "trustDirection", 0))
            tt  = int(attr(e, "trustType", 0))
            ta  = int(attr(e, "trustAttributes", 0))
            row = {
                "Name":       attr(e, "name"),
                "Direction":  TRUST_DIRECTION.get(td, str(td)),
                "Type":       TRUST_TYPE.get(tt, str(tt)),
                "Attributes": ", ".join(v for k, v in TRUST_ATTR.items() if ta & k),
                "Created":    str(attr(e, "whenCreated", "")),
            }
            results.append(row)
            flag = RED if "NON_TRANSITIVE" not in row["Attributes"] else ""
            print(f"  {flag}{row['Name']}{RESET} | Dir: {row['Direction']} | Type: {row['Type']} | Attrs: {row['Attributes']}")
        if not results:
            info("  No external trusts found")
        self.report["Domain Trusts"] = results

    # ── All Users ─────────────────────────────────────────────────────────────
    def enum_users(self):
        section("Domain Users")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(objectCategory=person)(objectClass=user))",
            ["sAMAccountName", "displayName", "mail", "title",
             "department", "description", "memberOf", "userAccountControl",
             "lastLogonTimestamp", "pwdLastSet", "whenCreated",
             "adminCount", "distinguishedName", "servicePrincipalName"],
        )
        results = []
        for e in entries:
            sam    = attr(e, "sAMAccountName")
            uac    = int(attr(e, "userAccountControl", 0) or 0)
            flags  = uac_flags(uac)
            last   = filetime_to_dt(attr(e, "lastLogonTimestamp"))
            pwdset = filetime_to_dt(attr(e, "pwdLastSet"))
            row    = {
                "Username":        sam,
                "DisplayName":     attr(e, "displayName"),
                "Email":           attr(e, "mail"),
                "Title":           attr(e, "title"),
                "Department":      attr(e, "department"),
                "Description":     attr(e, "description"),
                "AdminCount":      attr(e, "adminCount", 0),
                "Enabled":         "No" if uac & 0x0002 else "Yes",
                "PasswordExpires": "No" if uac & 0x10000 else "Yes",
                "PasswordNotReq":  "Yes" if uac & 0x0020 else "No",
                "LastLogon":       str(last) if last else "Never",
                "PwdLastSet":      str(pwdset) if pwdset else "Never",
                "Groups":          "; ".join(attr_list(e, "memberOf")),
                "SPNs":            "; ".join(attr_list(e, "servicePrincipalName")),
                "UAC":             ", ".join(flags),
                "DN":              attr(e, "distinguishedName"),
            }
            results.append(row)
            enabled_color = GREEN if row["Enabled"] == "Yes" else RED
            print(f"  {enabled_color}{sam}{RESET} | Enabled: {row['Enabled']} | AdminCount: {row['AdminCount']} | Last Logon: {row['LastLogon']}")
        success(f"  Total users: {len(results)}")
        self.report["Users"] = results

    # ── Kerberoastable Accounts ────────────────────────────────────────────────
    def enum_kerberoastable(self):
        section("Kerberoastable Accounts (SPNs on User Objects)")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "servicePrincipalName", "memberOf",
             "adminCount", "pwdLastSet", "lastLogonTimestamp",
             "userAccountControl", "distinguishedName"],
        )
        results = []
        for e in entries:
            sam  = attr(e, "sAMAccountName")
            spns = attr_list(e, "servicePrincipalName")
            adm  = attr(e, "adminCount", 0)
            pwd  = filetime_to_dt(attr(e, "pwdLastSet"))
            row  = {
                "Username":   sam,
                "SPNs":       spns,
                "AdminCount": adm,
                "PwdLastSet": str(pwd) if pwd else "Never",
                "DN":         attr(e, "distinguishedName"),
            }
            results.append(row)
            color = RED if adm else YELLOW
            print(f"  {color}{sam}{RESET} | AdminCount: {adm}")
            for spn in spns:
                print(f"    SPN: {spn}")
        if not results:
            info("  No kerberoastable accounts found")
        else:
            warn(f"  {len(results)} kerberoastable account(s) found — attempt AS-REP/TGS cracking")
        self.report["Kerberoastable"] = results

    # ── ASREPRoastable Accounts ───────────────────────────────────────────────
    def enum_asreproastable(self):
        section("ASREPRoastable Accounts (Kerberos Pre-Auth Disabled)")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
            ["sAMAccountName", "adminCount", "memberOf",
             "pwdLastSet", "lastLogonTimestamp", "distinguishedName"],
        )
        results = []
        for e in entries:
            sam = attr(e, "sAMAccountName")
            adm = attr(e, "adminCount", 0)
            pwd = filetime_to_dt(attr(e, "pwdLastSet"))
            row = {
                "Username":   sam,
                "AdminCount": adm,
                "PwdLastSet": str(pwd) if pwd else "Never",
                "DN":         attr(e, "distinguishedName"),
            }
            results.append(row)
            color = RED if adm else YELLOW
            print(f"  {color}{sam}{RESET} | AdminCount: {adm} | PwdLastSet: {row['PwdLastSet']}")
        if not results:
            info("  No ASREPRoastable accounts found")
        else:
            warn(f"  {len(results)} ASREPRoastable account(s) found")
        self.report["ASREPRoastable"] = results

    # ── Password Not Required ────────────────────────────────────────────────
    def enum_passwd_not_required(self):
        section("Accounts with Password Not Required (UAC: PASSWD_NOTREQD)")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))",
            ["sAMAccountName", "userAccountControl", "adminCount",
             "lastLogonTimestamp", "distinguishedName"],
        )
        results = []
        for e in entries:
            sam    = attr(e, "sAMAccountName")
            uac    = int(attr(e, "userAccountControl", 0) or 0)
            enabled = "No" if uac & 0x0002 else "Yes"
            row    = {
                "Username":   sam,
                "Enabled":    enabled,
                "AdminCount": attr(e, "adminCount", 0),
                "DN":         attr(e, "distinguishedName"),
            }
            results.append(row)
            print(f"  {YELLOW}{sam}{RESET} | Enabled: {enabled}")
        if not results:
            info("  No accounts with password not required")
        self.report["PasswordNotRequired"] = results

    # ── Never Logged On ───────────────────────────────────────────────────────
    def enum_never_logged_on(self):
        section("Enabled Accounts Never Logged On")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(lastLogonTimestamp=*)))",
            ["sAMAccountName", "whenCreated", "distinguishedName"],
        )
        results = []
        for e in entries:
            sam     = attr(e, "sAMAccountName")
            created = attr(e, "whenCreated", "")
            row     = {"Username": sam, "Created": str(created), "DN": attr(e, "distinguishedName")}
            results.append(row)
            print(f"  {sam} | Created: {created}")
        if not results:
            info("  No enabled accounts with no logon history")
        self.report["NeverLoggedOn"] = results

    # ── Descriptions with Potential Passwords ────────────────────────────────
    def enum_descriptions(self):
        section("Users/Computers with Notable Descriptions")
        keywords = ["pass", "pwd", "cred", "secret", "key", "hash", "token", "admin"]
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(|(objectClass=user)(objectClass=computer))(description=*))",
            ["sAMAccountName", "description", "distinguishedName"],
        )
        results = []
        for e in entries:
            sam  = attr(e, "sAMAccountName")
            desc = attr(e, "description", "")
            row  = {"Name": sam, "Description": desc, "DN": attr(e, "distinguishedName")}
            results.append(row)
            color = RED if any(k in desc.lower() for k in keywords) else WHITE
            print(f"  {color}{sam}{RESET}: {desc}")
        if not results:
            info("  No descriptions found")
        self.report["Descriptions"] = results

    # ── All Groups ────────────────────────────────────────────────────────────
    def enum_groups(self):
        section("Domain Groups")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(objectClass=group)",
            ["name", "sAMAccountName", "description", "member",
             "memberOf", "adminCount", "groupType", "distinguishedName"],
        )
        results = []
        for e in entries:
            name    = attr(e, "name")
            members = attr_list(e, "member")
            gt      = int(attr(e, "groupType", 0) or 0)
            # groupType bit 0x80000000 = security group
            is_sec  = bool(gt & 0x80000000)
            row     = {
                "Name":        name,
                "SAM":         attr(e, "sAMAccountName"),
                "Description": attr(e, "description"),
                "MemberCount": len(members),
                "Security":    "Yes" if is_sec else "No",
                "AdminCount":  attr(e, "adminCount", 0),
                "DN":          attr(e, "distinguishedName"),
            }
            results.append(row)
            color = RED if name.lower() in HIGH_VALUE_GROUPS else WHITE
            print(f"  {color}{name}{RESET} | Members: {len(members)} | Security: {row['Security']} | AdminCount: {row['AdminCount']}")
        success(f"  Total groups: {len(results)}")
        self.report["Groups"] = results

    # ── High-Value Group Memberships ──────────────────────────────────────────
    def enum_admin_groups(self):
        section("High-Value Group Memberships")
        results = []
        for grp_name in HIGH_VALUE_GROUPS:
            entries = ldap_search(
                self.conn, self.base_dn,
                f"(&(objectClass=group)(sAMAccountName={grp_name}))",
                ["name", "member", "distinguishedName"],
            )
            for e in entries:
                members = attr_list(e, "member")
                if members:
                    print(f"\n  {RED}{BOLD}{attr(e,'name')}{RESET}")
                    for m in members:
                        cn = m.split(",")[0].replace("CN=", "")
                        print(f"    → {cn}")
                        results.append({"Group": attr(e, "name"), "Member": cn, "MemberDN": m})
        if not results:
            info("  No members in high-value groups (or no access)")
        self.report["AdminGroupMembers"] = results

    # ── Computers ─────────────────────────────────────────────────────────────
    def enum_computers(self):
        section("Domain Computers")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
            ["name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
             "lastLogonTimestamp", "whenCreated", "userAccountControl",
             "distinguishedName", "servicePrincipalName"],
        )
        results = []
        for e in entries:
            uac     = int(attr(e, "userAccountControl", 0) or 0)
            enabled = "No" if uac & 0x0002 else "Yes"
            last    = filetime_to_dt(attr(e, "lastLogonTimestamp"))
            os_name = attr(e, "operatingSystem", "Unknown")
            row     = {
                "Name":    attr(e, "name"),
                "FQDN":    attr(e, "dNSHostName"),
                "OS":      os_name,
                "OSVer":   attr(e, "operatingSystemVersion"),
                "Enabled": enabled,
                "LastLogon": str(last) if last else "Never",
                "DN":      attr(e, "distinguishedName"),
            }
            results.append(row)
            color = RED if "windows xp" in os_name.lower() or "windows 7" in os_name.lower() \
                       or "2003" in os_name or "2008" in os_name else WHITE
            print(f"  {color}{row['Name']}{RESET} | {row['OS']} | Enabled: {enabled} | Last: {row['LastLogon']}")
        success(f"  Total computers: {len(results)}")
        self.report["Computers"] = results

    # ── Obsolete Operating Systems ────────────────────────────────────────────
    def enum_obsolete_os(self):
        section("Obsolete / End-of-Life Operating Systems")

        # (display_name, LDAP filter substring, EOL date, CVE-era note)
        OBSOLETE = [
            ("Windows XP",              "Windows XP",               "Apr 2014", "MS08-067, MS17-010, EternalBlue"),
            ("Windows Vista",           "Windows Vista",            "Apr 2017", "MS17-010, EternalBlue"),
            ("Windows 7",               "Windows 7",                "Jan 2020", "MS17-010, EternalBlue, ZeroLogon era"),
            ("Windows 8 / 8.1",         "Windows 8",                "Jan 2023", "Multiple unpatched RCEs post-EOL"),
            ("Windows Server 2000",     "Windows 2000",             "Jul 2010", "Numerous unauthenticated RCEs"),
            ("Windows Server 2003",     "Windows Server 2003",      "Jul 2015", "MS08-067, no SMBv2"),
            ("Windows Server 2008",     "Windows Server 2008",      "Jan 2020", "MS17-010, ZeroLogon era, CVE-2019-0708 BlueKeep"),
            ("Windows Server 2008 R2",  "Windows Server 2008 R2",   "Jan 2020", "MS17-010, ZeroLogon era, CVE-2019-0708 BlueKeep"),
            ("Windows Server 2012",     "Windows Server 2012",      "Oct 2023", "Post-EOL unpatched vulnerabilities"),
            ("Windows Server 2012 R2",  "Windows Server 2012 R2",   "Oct 2023", "Post-EOL unpatched vulnerabilities"),
        ]

        all_results = []

        for display_name, os_substring, eol_date, notes in OBSOLETE:
            entries = ldap_search(
                self.conn, self.base_dn,
                f"(&(objectCategory=computer)(operatingSystem=*{os_substring}*))",
                ["name", "dNSHostName", "operatingSystem", "operatingSystemVersion",
                 "lastLogonTimestamp", "userAccountControl", "distinguishedName"],
            )
            if not entries:
                continue

            print(f"\n  {RED}{BOLD}[EOL: {eol_date}] {display_name}{RESET}  {YELLOW}— {notes}{RESET}")
            for e in entries:
                uac      = int(attr(e, "userAccountControl", 0) or 0)
                enabled  = "No" if uac & 0x0002 else "Yes"
                last     = filetime_to_dt(attr(e, "lastLogonTimestamp"))
                os_ver   = attr(e, "operatingSystemVersion", "")
                hostname = attr(e, "name")
                fqdn     = attr(e, "dNSHostName", "")
                row = {
                    "Hostname":  hostname,
                    "FQDN":      fqdn,
                    "OS":        attr(e, "operatingSystem"),
                    "Version":   os_ver,
                    "EOL Date":  eol_date,
                    "Risk Notes":notes,
                    "Enabled":   enabled,
                    "LastLogon": str(last) if last else "Never",
                    "DN":        attr(e, "distinguishedName"),
                }
                all_results.append(row)
                en_color = RED if enabled == "Yes" else YELLOW
                print(f"    {en_color}{hostname}{RESET} ({fqdn}) | {os_ver} | Enabled: {enabled} | Last Logon: {row['LastLogon']}")

        if not all_results:
            success("  No end-of-life operating systems detected")
        else:
            print()
            warn(f"  {RED}{BOLD}{len(all_results)} EOL system(s) found{RESET} — these should be treated as critical findings")
            # Break down by OS for quick triage
            from collections import Counter
            counts = Counter(r["OS"] for r in all_results)
            for os_name, count in sorted(counts.items()):
                print(f"    {RED}•{RESET} {os_name}: {count}")

        self.report["ObsoleteOS"] = all_results

    # ── Unconstrained Delegation ─────────────────────────────────────────────
    def enum_unconstrained(self):
        section("Unconstrained Delegation (non-DC)")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(|(objectClass=user)(objectClass=computer))"
            "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
            ["sAMAccountName", "dNSHostName", "userAccountControl",
             "distinguishedName", "objectClass"],
        )
        results = []
        for e in entries:
            sam = attr(e, "sAMAccountName")
            row = {"Name": sam, "FQDN": attr(e, "dNSHostName"), "DN": attr(e, "distinguishedName")}
            results.append(row)
            warn(f"  [UNCONSTRAINED] {RED}{sam}{RESET}")
        if not results:
            info("  No unconstrained delegation (non-DC) found")
        self.report["UnconstrainedDelegation"] = results

    # ── Constrained Delegation ────────────────────────────────────────────────
    def enum_constrained(self):
        section("Constrained Delegation")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(|(objectClass=user)(objectClass=computer))"
            "(msDS-AllowedToDelegateTo=*))",
            ["sAMAccountName", "msDS-AllowedToDelegateTo",
             "userAccountControl", "distinguishedName"],
        )
        results = []
        for e in entries:
            sam      = attr(e, "sAMAccountName")
            services = attr_list(e, "msDS-AllowedToDelegateTo")
            uac      = int(attr(e, "userAccountControl", 0) or 0)
            proto    = "Protocol Transition (Any Auth)" if uac & 0x01000000 else "Kerberos Only"
            row      = {"Name": sam, "DelegateTo": services, "Protocol": proto, "DN": attr(e, "distinguishedName")}
            results.append(row)
            print(f"  {YELLOW}{sam}{RESET} | {proto}")
            for svc in services:
                print(f"    → {svc}")
        if not results:
            info("  No constrained delegation found")
        self.report["ConstrainedDelegation"] = results

    # ── RBCD ──────────────────────────────────────────────────────────────────
    def enum_rbcd(self):
        section("Resource-Based Constrained Delegation (RBCD)")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
            ["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity",
             "distinguishedName"],
        )
        results = []
        for e in entries:
            sam = attr(e, "sAMAccountName")
            row = {"Name": sam, "DN": attr(e, "distinguishedName")}
            results.append(row)
            warn(f"  [RBCD] {RED}{sam}{RESET} has msDS-AllowedToActOnBehalfOfOtherIdentity set")
        if not results:
            info("  No RBCD configurations found")
        self.report["RBCD"] = results

    # ── OUs ────────────────────────────────────────────────────────────────────
    def enum_ous(self):
        section("Organisational Units (OUs)")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(objectClass=organizationalUnit)",
            ["name", "distinguishedName", "description", "gPLink"],
        )
        results = []
        for e in entries:
            row = {
                "Name":        attr(e, "name"),
                "Description": attr(e, "description"),
                "GPLinks":     attr(e, "gPLink"),
                "DN":          attr(e, "distinguishedName"),
            }
            results.append(row)
            print(f"  {row['Name']} | {row['DN']}")
        success(f"  Total OUs: {len(results)}")
        self.report["OUs"] = results

    # ── GPOs ───────────────────────────────────────────────────────────────────
    def enum_gpos(self):
        section("Group Policy Objects (GPOs)")
        entries = ldap_search(
            self.conn, f"CN=Policies,CN=System,{self.base_dn}",
            "(objectClass=groupPolicyContainer)",
            ["displayName", "gPCFileSysPath", "whenCreated",
             "whenChanged", "flags", "distinguishedName", "name"],
        )
        results = []
        for e in entries:
            row = {
                "Name":       attr(e, "displayName"),
                "GUID":       attr(e, "name"),
                "Path":       attr(e, "gPCFileSysPath"),
                "Created":    str(attr(e, "whenCreated", "")),
                "Modified":   str(attr(e, "whenChanged", "")),
                "Flags":      attr(e, "flags", 0),
                "DN":         attr(e, "distinguishedName"),
            }
            results.append(row)
            print(f"  {row['Name']} | GUID: {row['GUID']} | Modified: {row['Modified']}")
        success(f"  Total GPOs: {len(results)}")
        self.report["GPOs"] = results

    # ── Subnets / Sites ────────────────────────────────────────────────────────
    def enum_subnets(self):
        section("AD Sites and Subnets")
        site_entries = ldap_search(
            self.conn,
            f"CN=Sites,CN=Configuration,{self.base_dn}",
            "(objectClass=site)",
            ["name", "distinguishedName"],
        )
        subnet_entries = ldap_search(
            self.conn,
            f"CN=Subnets,CN=Sites,CN=Configuration,{self.base_dn}",
            "(objectClass=subnet)",
            ["name", "siteObject", "description", "location"],
        )
        results = {"Sites": [], "Subnets": []}
        for e in site_entries:
            row = {"Name": attr(e, "name"), "DN": attr(e, "distinguishedName")}
            results["Sites"].append(row)
            print(f"  [Site] {row['Name']}")
        for e in subnet_entries:
            row = {
                "Subnet":      attr(e, "name"),
                "Site":        attr(e, "siteObject"),
                "Description": attr(e, "description"),
                "Location":    attr(e, "location"),
            }
            results["Subnets"].append(row)
            print(f"    [Subnet] {row['Subnet']} → {row['Site']}")
        self.report["Sites_Subnets"] = results

    # ── ACLs (Interesting DACLs) ──────────────────────────────────────────────
    def enum_acls(self):
        section("Interesting ACEs / DACLs")
        # Focus: who has GenericAll, GenericWrite, WriteDacl, WriteOwner, etc.
        # on user/group/computer objects (excluding self, system, admin)
        SYSTEM_SIDS = {
            "S-1-5-18", "S-1-5-19", "S-1-5-20",
            "S-1-5-32-544", "S-1-5-32-548", "S-1-5-32-549",
            "S-1-3-0", "S-1-3-1",
        }
        entries = ldap_search(
            self.conn, self.base_dn,
            "(|(objectClass=user)(objectClass=group)(objectClass=computer))",
            ["nTSecurityDescriptor", "sAMAccountName", "distinguishedName"],
        )
        results = []
        for e in entries:
            target_name = attr(e, "sAMAccountName", attr(e, "distinguishedName"))
            sd = e.get("attributes", {}).get("nTSecurityDescriptor")
            if not sd:
                continue
            # ldap3 returns nTSecurityDescriptor as bytes or dict; parse raw if bytes
            if isinstance(sd, bytes):
                # We'd need impacket's ldaptypes to parse; skip for now
                # and flag that we'd need impacket for full ACL parsing
                continue
            # If ldap3 parsed it (dict-like), iterate ACEs
            dacl = getattr(sd, "dacl", None)
            if not dacl:
                continue
            for ace in getattr(dacl, "aces", []):
                sid   = str(getattr(ace, "sid", ""))
                mask  = getattr(ace, "mask", 0)
                rights = [name for val, name in ACCESS_MASK_MAP.items() if mask & val]
                if sid in SYSTEM_SIDS:
                    continue
                for right in INTERESTING_RIGHTS:
                    if any(right.lower() in r.lower() for r in rights):
                        row = {"Target": target_name, "PrincipalSID": sid, "Right": right}
                        results.append(row)
                        warn(f"  {sid} → {RED}{right}{RESET} on {target_name}")
                        break
        if not results:
            info("  No interesting ACEs found (nTSecurityDescriptor requires elevated bind for full parse)")
        self.report["InterestingACEs"] = results

    # ── LAPS ──────────────────────────────────────────────────────────────────
    def enum_laps(self):
        section("LAPS (Local Administrator Password Solution)")
        # Check if LAPS attribute exists in schema
        entries_laps = ldap_search(
            self.conn, self.base_dn,
            "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))",
            ["name", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "distinguishedName"],
        )
        results = []
        laps_deployed = False
        for e in entries_laps:
            laps_deployed = True
            name    = attr(e, "name")
            pwd     = attr(e, "ms-Mcs-AdmPwd", "(no read access)")
            exp_ft  = attr(e, "ms-Mcs-AdmPwdExpirationTime")
            exp_dt  = filetime_to_dt(exp_ft)
            row     = {
                "Computer": name,
                "Password": pwd,
                "Expires":  str(exp_dt) if exp_dt else "Unknown",
                "DN":       attr(e, "distinguishedName"),
            }
            results.append(row)
            color = GREEN if pwd != "(no read access)" else YELLOW
            print(f"  {color}{name}{RESET} | Password: {pwd} | Expires: {row['Expires']}")

        # Also check computers that DON'T have LAPS (ms-Mcs-AdmPwd missing)
        entries_no_laps = ldap_search(
            self.conn, self.base_dn,
            "(&(objectCategory=computer)(!(ms-Mcs-AdmPwd=*))(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))",
            ["name", "distinguishedName"],
        )
        no_laps = []
        for e in entries_no_laps:
            no_laps.append({"Computer": attr(e, "name"), "DN": attr(e, "distinguishedName")})

        if not laps_deployed and not results:
            warn("  LAPS does not appear to be deployed (or ms-Mcs-AdmPwd attribute not accessible)")
        else:
            if no_laps:
                warn(f"  {len(no_laps)} computers without LAPS coverage:")
                for c in no_laps[:10]:
                    print(f"    {c['Computer']}")
                if len(no_laps) > 10:
                    print(f"    ... and {len(no_laps)-10} more")
        self.report["LAPS"] = results
        self.report["LAPS_NoCoverage"] = no_laps

    # ── User-Created Computer Objects ─────────────────────────────────────────
    def enum_user_created_objects(self):
        section("User-Created Computer Objects (Non-Admin)")
        SYSTEM_CREATORS = {
            "S-1-5-18", "S-1-5-32-544", "NT AUTHORITY\\SYSTEM",
            "BUILTIN\\Administrators",
        }
        entries = ldap_search(
            self.conn, self.base_dn,
            "(objectCategory=computer)",
            ["name", "mS-DS-CreatorSID", "sAMAccountName", "distinguishedName"],
        )
        results = []
        for e in entries:
            creator = attr(e, "mS-DS-CreatorSID", "")
            if creator and creator not in SYSTEM_CREATORS:
                row = {
                    "Computer":   attr(e, "name"),
                    "CreatorSID": creator,
                    "DN":         attr(e, "distinguishedName"),
                }
                results.append(row)
                warn(f"  {YELLOW}{row['Computer']}{RESET} created by non-system SID: {creator}")
        if not results:
            info("  No user-created computer objects found")
        self.report["UserCreatedComputers"] = results

    # ── Password Spraying - Empty Passwords ───────────────────────────────────
    def enum_empty_passwords(self):
        section("Accounts with Empty / Null Passwords (UAC: PASSWD_NOTREQD + enabled)")
        # Best effort: flag accounts with PASSWD_NOTREQD + enabled + never set password
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(objectCategory=person)(objectClass=user)"
            "(userAccountControl:1.2.840.113556.1.4.803:=32)"
            "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
            ["sAMAccountName", "pwdLastSet", "distinguishedName"],
        )
        results = []
        for e in entries:
            sam    = attr(e, "sAMAccountName")
            pwdset = attr(e, "pwdLastSet", 0)
            if not pwdset or int(pwdset) == 0:
                row = {"Username": sam, "PwdLastSet": "Never (0)", "DN": attr(e, "distinguishedName")}
                results.append(row)
                warn(f"  {RED}{sam}{RESET} — possible empty/null password")
        if not results:
            info("  No accounts with probable empty passwords")
        self.report["EmptyPasswords"] = results

    # ── Password Policy ───────────────────────────────────────────────────────
    def enum_password_policy(self):
        section("Default Domain Password Policy")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(objectClass=domain)",
            ["minPwdLength", "minPwdAge", "maxPwdAge",
             "lockoutThreshold", "lockoutDuration", "lockoutObservationWindow",
             "pwdHistoryLength", "pwdProperties"],
        )
        PWD_PROPS = {
            1: "DOMAIN_PASSWORD_COMPLEX",
            2: "DOMAIN_PASSWORD_NO_ANON_CHANGE",
            4: "DOMAIN_PASSWORD_NO_CLEAR_CHANGE",
            8: "DOMAIN_LOCKOUT_ADMINS",
            16: "DOMAIN_PASSWORD_STORE_CLEARTEXT",
            32: "DOMAIN_REFUSE_PASSWORD_CHANGE",
        }
        results = []
        for e in entries:
            props     = int(attr(e, "pwdProperties", 0) or 0)
            prop_list = [v for k, v in PWD_PROPS.items() if props & k]
            # Convert 100-ns intervals
            def ns100_to_days(v):
                try: return abs(int(v)) // 864000000000
                except: return "N/A"
            row = {
                "MinPwdLength":     attr(e, "minPwdLength", "N/A"),
                "MaxPwdAge_days":   ns100_to_days(attr(e, "maxPwdAge")),
                "LockoutThreshold": attr(e, "lockoutThreshold", "N/A"),
                "PwdHistoryLength": attr(e, "pwdHistoryLength", "N/A"),
                "Complexity":       "Enabled" if props & 1 else "Disabled",
                "Props":            prop_list,
            }
            results.append(row)
            for k, v in row.items():
                print(f"  {BOLD}{k:<25}{RESET}: {v}")
            if not (props & 1):
                warn("  Password complexity is DISABLED")
        self.report["PasswordPolicy"] = results

    # ── Fine-Grained Password Policies ───────────────────────────────────────
    def enum_fine_grained_pwd(self):
        section("Fine-Grained Password Policies (PSOs)")
        entries = ldap_search(
            self.conn,
            f"CN=Password Settings Container,CN=System,{self.base_dn}",
            "(objectClass=msDS-PasswordSettings)",
            ["name", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold",
             "msDS-PasswordComplexityEnabled", "msDS-PSOAppliesTo",
             "msDS-PasswordSettingsPrecedence"],
        )
        results = []
        for e in entries:
            name = attr(e, "name")
            row  = {
                "Name":       name,
                "MinLength":  attr(e, "msDS-MinimumPasswordLength", "N/A"),
                "Lockout":    attr(e, "msDS-LockoutThreshold", "N/A"),
                "Complexity": attr(e, "msDS-PasswordComplexityEnabled", "N/A"),
                "Precedence": attr(e, "msDS-PasswordSettingsPrecedence", "N/A"),
                "AppliesTo":  attr_list(e, "msDS-PSOAppliesTo"),
            }
            results.append(row)
            print(f"  {YELLOW}{name}{RESET} | MinLen: {row['MinLength']} | Lockout: {row['Lockout']} | Complexity: {row['Complexity']}")
            for t in row["AppliesTo"]:
                print(f"    Applies to: {t}")
        if not results:
            info("  No fine-grained password policies found")
        self.report["FineGrainedPwdPolicies"] = results

    # ── AdminSDHolder protected accounts ──────────────────────────────────────
    def enum_adminsdholder(self):
        section("AdminSDHolder Protected Accounts (adminCount=1)")
        entries = ldap_search(
            self.conn, self.base_dn,
            "(&(adminCount=1)(objectCategory=person)(objectClass=user))",
            ["sAMAccountName", "memberOf", "userAccountControl",
             "lastLogonTimestamp", "distinguishedName"],
        )
        results = []
        for e in entries:
            sam     = attr(e, "sAMAccountName")
            uac     = int(attr(e, "userAccountControl", 0) or 0)
            enabled = "No" if uac & 0x0002 else "Yes"
            last    = filetime_to_dt(attr(e, "lastLogonTimestamp"))
            row     = {
                "Username":   sam,
                "Enabled":    enabled,
                "LastLogon":  str(last) if last else "Never",
                "DN":         attr(e, "distinguishedName"),
            }
            results.append(row)
            color = RED if enabled == "Yes" else YELLOW
            print(f"  {color}{sam}{RESET} | Enabled: {enabled} | Last Logon: {row['LastLogon']}")
        success(f"  {len(results)} AdminSDHolder-protected accounts")
        self.report["AdminSDHolder"] = results

    # ── Summary ───────────────────────────────────────────────────────────────
    def print_summary(self):
        section("Enumeration Summary")
        counts = {
            "Users":            len(self.report.get("Users", [])),
            "Computers":        len(self.report.get("Computers", [])),
            "Groups":           len(self.report.get("Groups", [])),
            "Domain Controllers": len(self.report.get("Domain Controllers", [])),
            "Kerberoastable":   len(self.report.get("Kerberoastable", [])),
            "ASREPRoastable":   len(self.report.get("ASREPRoastable", [])),
            "Unconstrained Del.": len(self.report.get("UnconstrainedDelegation", [])),
            "RBCD":             len(self.report.get("RBCD", [])),
            "Obsolete OS":      len(self.report.get("ObsoleteOS", [])),
            "Trusts":           len(self.report.get("Domain Trusts", [])),
            "GPOs":             len(self.report.get("GPOs", [])),
            "OUs":              len(self.report.get("OUs", [])),
        }
        for name, count in counts.items():
            color = RED if count > 0 and name in {
                "Kerberoastable", "ASREPRoastable",
                "Unconstrained Del.", "RBCD", "Obsolete OS",
            } else GREEN
            print(f"  {BOLD}{name:<30}{RESET}: {color}{count}{RESET}")

    # ── JSON export ───────────────────────────────────────────────────────────
    def save_json(self, path: str):
        def _serialize(obj):
            if isinstance(obj, (datetime.datetime, datetime.date)):
                return obj.isoformat()
            if isinstance(obj, bytes):
                return obj.hex()
            return str(obj)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=2, default=_serialize)
        success(f"JSON report saved to {path}")

    # ── HTML report ───────────────────────────────────────────────────────────
    def save_html(self, path: str):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        css = """
        :root{--bg:#0d1117;--surface:#161b22;--border:#30363d;--text:#e6edf3;
              --muted:#8b949e;--accent:#58a6ff;--red:#f85149;--green:#3fb950;
              --yellow:#d29922;--cyan:#39d353;}
        *{box-sizing:border-box;margin:0;padding:0;}
        body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:14px;line-height:1.6;}
        header{background:var(--surface);border-bottom:1px solid var(--border);padding:20px 40px;
               display:flex;align-items:center;justify-content:space-between;}
        header h1{color:var(--accent);font-size:22px;letter-spacing:1px;}
        header span{color:var(--muted);font-size:12px;}
        nav{background:var(--surface);border-bottom:1px solid var(--border);
            padding:10px 40px;display:flex;flex-wrap:wrap;gap:8px;}
        nav a{color:var(--muted);text-decoration:none;font-size:12px;padding:4px 10px;
              border-radius:4px;border:1px solid var(--border);transition:all .2s;}
        nav a:hover{color:var(--accent);border-color:var(--accent);}
        main{padding:30px 40px;max-width:1400px;margin:0 auto;}
        section{margin-bottom:40px;}
        section h2{color:var(--accent);font-size:16px;margin-bottom:14px;
                   padding-bottom:8px;border-bottom:1px solid var(--border);}
        .badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;}
        .badge-red{background:#3d1a1a;color:var(--red);}
        .badge-green{background:#1a3d1a;color:var(--green);}
        .badge-yellow{background:#3d2e0a;color:var(--yellow);}
        .badge-blue{background:#0d2740;color:var(--accent);}
        table{width:100%;border-collapse:collapse;font-size:13px;}
        th{background:#1c2128;color:var(--muted);text-align:left;padding:8px 12px;
           font-weight:600;border-bottom:2px solid var(--border);position:sticky;top:0;}
        td{padding:7px 12px;border-bottom:1px solid #21262d;vertical-align:top;word-break:break-all;}
        tr:hover td{background:#1c2128;}
        .table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:6px;}
        .finding-high{color:var(--red);}
        .finding-med {color:var(--yellow);}
        .finding-info{color:var(--cyan);}
        .stat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;margin-bottom:30px;}
        .stat-card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
                   padding:16px;text-align:center;}
        .stat-card .num{font-size:32px;font-weight:700;color:var(--accent);}
        .stat-card .lbl{color:var(--muted);font-size:11px;margin-top:4px;}
        .empty{color:var(--muted);font-style:italic;padding:16px;}
        """

        def make_table(rows, highlight_col=None, highlight_val=None, severity_map=None):
            if not rows:
                return '<p class="empty">No data found.</p>'
            if isinstance(rows, dict):
                # Nested dict (e.g. Sites_Subnets)
                out = ""
                for k, v in rows.items():
                    out += f"<h3 style='color:var(--muted);margin:12px 0 8px'>{k}</h3>"
                    out += make_table(v)
                return out
            # Filter out non-table-able items
            rows = [r for r in rows if isinstance(r, dict)]
            if not rows:
                return '<p class="empty">No data found.</p>'
            cols = list(rows[0].keys())
            html = '<div class="table-wrap"><table><thead><tr>'
            for c in cols:
                html += f"<th>{c}</th>"
            html += "</tr></thead><tbody>"
            for row in rows:
                html += "<tr>"
                for c in cols:
                    v = row.get(c, "")
                    if isinstance(v, list):
                        v = "<br>".join(str(i) for i in v)
                    else:
                        v = str(v)
                    cls = ""
                    if severity_map and c in severity_map:
                        cls = severity_map[c].get(v, "")
                    html += f'<td class="{cls}">{v}</td>'
                html += "</tr>"
            html += "</tbody></table></div>"
            return html

        # Build navigation
        sections_nav = "".join(f'<a href="#{k.replace(" ","_")}">{k}</a>'
                               for k in self.report.keys())

        # Stat cards
        stat_keys = {
            "Users": "Users",
            "Computers": "Computers",
            "Groups": "Groups",
            "Kerberoastable": "Kerberoastable",
            "ASREPRoastable": "ASREPRoastable",
            "UnconstrainedDelegation": "Unconstrained Del.",
            "RBCD": "RBCD",
            "ObsoleteOS": "Obsolete OS",
        }
        stats_html = '<div class="stat-grid">'
        for key, label in stat_keys.items():
            count = len(self.report.get(key, []))
            color = "var(--red)" if count > 0 and key in {
                "Kerberoastable", "ASREPRoastable", "UnconstrainedDelegation", "RBCD", "ObsoleteOS"
            } else "var(--accent)"
            stats_html += f'<div class="stat-card"><div class="num" style="color:{color}">{count}</div><div class="lbl">{label}</div></div>'
        stats_html += "</div>"

        # Sections
        sections_html = ""
        for name, data in self.report.items():
            anchor = name.replace(" ", "_")
            sections_html += f'<section id="{anchor}"><h2>{name}</h2>{make_table(data)}</section>'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Enumeration Report — {self.args.domain}</title>
<style>{css}</style>
</head>
<body>
<header>
  <h1>🔍 Active Directory Enumeration Report</h1>
  <span>Domain: <strong>{self.args.domain}</strong> &nbsp;|&nbsp; DC: {self.args.dc_ip} &nbsp;|&nbsp; {now}</span>
</header>
<nav>{sections_nav}</nav>
<main>
{stats_html}
{sections_html}
</main>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        success(f"HTML report saved to {path}")


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="ad_enum.py — Python port of Invoke-ADEnum",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # Connection
    conn = p.add_argument_group("Connection")
    conn.add_argument("--dc-ip",   required=True, help="IP of the Domain Controller")
    conn.add_argument("--domain",  required=True, help="Domain FQDN (e.g. corp.local)")
    conn.add_argument("-u", "--username", default="", help="Username")
    conn.add_argument("-p", "--password", default="", help="Plaintext password")
    conn.add_argument("--hashes",  default="", help="NTLM hashes LM:NT (pass-the-hash)")
    conn.add_argument("--ldaps",   action="store_true", help="Use LDAPS (port 636)")

    # Modules
    mod = p.add_argument_group("Modules (default: run all)")
    mod.add_argument("--domain-info",    action="store_true", help="Domain info")
    mod.add_argument("--forest",         action="store_true", help="Forest/schema info")
    mod.add_argument("--dcs",            action="store_true", help="Domain controllers")
    mod.add_argument("--trusts",         action="store_true", help="Domain trusts")
    mod.add_argument("--users",          action="store_true", help="All users")
    mod.add_argument("--kerberoastable", action="store_true", help="Kerberoastable accounts")
    mod.add_argument("--asreproastable", action="store_true", help="ASREPRoastable accounts")
    mod.add_argument("--passwd-not-req", action="store_true", help="Password not required")
    mod.add_argument("--never-logged-on",action="store_true", help="Never logged on")
    mod.add_argument("--descriptions",   action="store_true", help="Notable descriptions")
    mod.add_argument("--groups",         action="store_true", help="All groups")
    mod.add_argument("--admin-groups",   action="store_true", help="High-value group members")
    mod.add_argument("--computers",      action="store_true", help="All computers")
    mod.add_argument("--unconstrained",  action="store_true", help="Unconstrained delegation")
    mod.add_argument("--constrained",    action="store_true", help="Constrained delegation")
    mod.add_argument("--rbcd",           action="store_true", help="Resource-based constrained delegation")
    mod.add_argument("--ous",            action="store_true", help="Organisational units")
    mod.add_argument("--gpos",           action="store_true", help="Group Policy Objects")
    mod.add_argument("--subnets",        action="store_true", help="AD Sites and Subnets")
    mod.add_argument("--acls",           action="store_true", help="Interesting ACEs/DACLs")
    mod.add_argument("--laps",           action="store_true", help="LAPS deployment and passwords")
    mod.add_argument("--user-created",   action="store_true", help="User-created computer objects")
    mod.add_argument("--empty-passwords",action="store_true", help="Accounts with probable empty passwords")
    mod.add_argument("--password-policy",action="store_true", help="Default password policy")
    mod.add_argument("--fine-grained",   action="store_true", help="Fine-grained password policies")
    mod.add_argument("--adminsdholder",  action="store_true", help="AdminSDHolder protected accounts")
    mod.add_argument("--obsolete-os",    action="store_true", help="End-of-life / obsolete operating systems")

    # Output
    out = p.add_argument_group("Output")
    out.add_argument("--report", action="store_true", help="Generate HTML report")
    out.add_argument("--json",   action="store_true", help="Generate JSON output")
    out.add_argument("--out-dir", default=".", help="Output directory (default: current dir)")

    return p.parse_args()


def run_module(flag: bool, all_flag: bool, fn):
    """Run a module if its flag is set, or if running all."""
    if flag or all_flag:
        try:
            fn()
        except Exception as exc:
            error(f"Module error: {exc}")


def main():
    banner()
    args = parse_args()

    # If no individual modules specified → run all
    module_flags = [
        args.domain_info, args.forest, args.dcs, args.trusts,
        args.users, args.kerberoastable, args.asreproastable,
        args.passwd_not_req, args.never_logged_on, args.descriptions,
        args.groups, args.admin_groups, args.computers,
        args.unconstrained, args.constrained, args.rbcd,
        args.ous, args.gpos, args.subnets, args.acls,
        args.laps, args.user_created, args.empty_passwords,
        args.password_policy, args.fine_grained, args.adminsdholder,
        args.obsolete_os,
    ]
    run_all = not any(module_flags)

    conn = connect_ldap(args)
    e    = ADEnum(conn, args)

    run_module(args.domain_info,     run_all, e.enum_domain)
    run_module(args.forest,          run_all, e.enum_forest)
    run_module(args.dcs,             run_all, e.enum_dcs)
    run_module(args.trusts,          run_all, e.enum_trusts)
    run_module(args.password_policy, run_all, e.enum_password_policy)
    run_module(args.fine_grained,    run_all, e.enum_fine_grained_pwd)
    run_module(args.users,           run_all, e.enum_users)
    run_module(args.kerberoastable,  run_all, e.enum_kerberoastable)
    run_module(args.asreproastable,  run_all, e.enum_asreproastable)
    run_module(args.passwd_not_req,  run_all, e.enum_passwd_not_required)
    run_module(args.never_logged_on, run_all, e.enum_never_logged_on)
    run_module(args.descriptions,    run_all, e.enum_descriptions)
    run_module(args.empty_passwords, run_all, e.enum_empty_passwords)
    run_module(args.adminsdholder,   run_all, e.enum_adminsdholder)
    run_module(args.groups,          run_all, e.enum_groups)
    run_module(args.admin_groups,    run_all, e.enum_admin_groups)
    run_module(args.computers,       run_all, e.enum_computers)
    run_module(args.obsolete_os,     run_all, e.enum_obsolete_os)
    run_module(args.unconstrained,   run_all, e.enum_unconstrained)
    run_module(args.constrained,     run_all, e.enum_constrained)
    run_module(args.rbcd,            run_all, e.enum_rbcd)
    run_module(args.ous,             run_all, e.enum_ous)
    run_module(args.gpos,            run_all, e.enum_gpos)
    run_module(args.subnets,         run_all, e.enum_subnets)
    run_module(args.acls,            run_all, e.enum_acls)
    run_module(args.laps,            run_all, e.enum_laps)
    run_module(args.user_created,    run_all, e.enum_user_created_objects)

    e.print_summary()

    # Output
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.json or run_all:
        e.save_json(str(out_dir / f"ad_enum_{args.domain}_{ts}.json"))

    if args.report or run_all:
        e.save_html(str(out_dir / f"ad_enum_{args.domain}_{ts}.html"))


if __name__ == "__main__":
    main()
