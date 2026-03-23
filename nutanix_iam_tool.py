#!/usr/bin/env python3
"""
nutanix_iam_tool.py
-------------------------------------------------------------------------------
Export and import Nutanix Prism Central roles and authorization policies
(v4 IAM API) to/from human-readable, editable XML files.

See README.md for full usage documentation.

Dependencies: pip install requests
-------------------------------------------------------------------------------
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import sys
import textwrap
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests.auth import HTTPBasicAuth

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ===========================================================================
#  Prism Central API client
# ===========================================================================

class PrismClient:
    """Thin wrapper around the Nutanix Prism Central v4 IAM/authz API.

    Roles and authorization policies sit under different API version prefixes
    depending on the Prism Central release:

      Roles:    api/iam/v4.0/authz/roles
      Policies: api/iam/v4.0.b1/authz/authorization-policies  (pre-GA PCs)
                api/iam/v4.0/authz/authorization-policies      (pc.2024.3+)

    The resource name is hyphenated in the URL ("authorization-policies"),
    not camelCase.

    Both base paths are overridable via --roles-api-base / --policies-api-base
    without any code changes.
    """

    _DEFAULT_ROLES_BASE    = "api/iam/v4.0/authz"
    _DEFAULT_POLICIES_BASE = "api/iam/v4.0.b1/authz"

    def __init__(self, host, username, password,
                 port=9440, verify_ssl=False,
                 roles_api_base=None, policies_api_base=None):
        self.base_url      = "https://{}:{}".format(host, port)
        self.roles_base    = (roles_api_base    or self._DEFAULT_ROLES_BASE).rstrip("/")
        self.policies_base = (policies_api_base or self._DEFAULT_POLICIES_BASE).rstrip("/")
        self.session = requests.Session()
        self.session.auth   = HTTPBasicAuth(username, password)
        self.session.verify = verify_ssl
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept":       "application/json",
        })

    # -- internals -----------------------------------------------------------

    def _roles_url(self, path):
        return "{}/{}/{}".format(self.base_url, self.roles_base, path.lstrip("/"))

    def _policies_url(self, path):
        return "{}/{}/{}".format(self.base_url, self.policies_base, path.lstrip("/"))

    def _raise(self, resp):
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        raise RuntimeError(
            "HTTP {} {} {}\n{}".format(
                resp.status_code,
                resp.request.method,
                resp.request.url,
                json.dumps(detail, indent=2),
            )
        )

    def _paginate(self, url):
        """Fetch all pages from a list endpoint and return the combined data list."""
        items, page, limit = [], 0, 50
        while True:
            r = self.session.get(url, params={"$page": page, "$limit": limit})
            if not r.ok:
                self._raise(r)
            body  = r.json()
            data  = body.get("data") or []
            items.extend(data)
            total = (body.get("metadata") or {}).get(
                "totalAvailableResults", len(items)
            )
            page += 1
            if len(items) >= total:
                break
        return items

    def _get_etag(self, url):
        """GET a single resource and return its ETag value.

        The v4 API requires optimistic concurrency control on PUT requests.
        The current ETag must be supplied as the If-Match header; without it
        the server returns HTTP 428 Precondition Required.

        ETag location varies by PC build:
          - Standard: ETag response header
          - Older builds: embedded in response body under $reserved.ETag
        """
        r = self.session.get(url)
        if not r.ok:
            self._raise(r)
        # Prefer the standard HTTP header
        etag = r.headers.get("ETag") or r.headers.get("Etag") or ""
        if not etag:
            # Fall back to body-embedded ETag present on some older builds
            reserved = r.json().get("$reserved") or {}
            etag = reserved.get("ETag") or reserved.get("Etag") or ""
        return etag

    # -- roles ---------------------------------------------------------------

    def list_roles(self):
        return self._paginate(self._roles_url("roles"))

    def create_role(self, payload):
        r = self.session.post(self._roles_url("roles"), json=payload)
        if not r.ok:
            self._raise(r)
        return r.json()

    def update_role(self, ext_id, payload):
        url  = self._roles_url("roles/{}".format(ext_id))
        etag = self._get_etag(url)
        headers = {"If-Match": etag} if etag else {}
        r = self.session.put(url, json=payload, headers=headers)
        if not r.ok:
            self._raise(r)
        return r.json()

    def find_role_by_name(self, name):
        for role in self.list_roles():
            if role.get("displayName") == name:
                return role
        return None

    # -- authorization policies ----------------------------------------------
    # Resource path is hyphenated: "authorization-policies"

    def list_policies(self):
        return self._paginate(self._policies_url("authorization-policies"))

    def create_policy(self, payload):
        r = self.session.post(
            self._policies_url("authorization-policies"), json=payload
        )
        if not r.ok:
            self._raise(r)
        return r.json()

    def update_policy(self, ext_id, payload):
        url  = self._policies_url("authorization-policies/{}".format(ext_id))
        etag = self._get_etag(url)
        headers = {"If-Match": etag} if etag else {}
        r = self.session.put(url, json=payload, headers=headers)
        if not r.ok:
            self._raise(r)
        return r.json()

    def find_policy_by_name(self, name):
        for pol in self.list_policies():
            if pol.get("displayName") == name:
                return pol
        return None


# ===========================================================================
#  Shared XML utilities
# ===========================================================================

def _sub(parent, tag, text=None):
    """Create a SubElement, optionally setting its text content."""
    el = ET.SubElement(parent, tag)
    if text is not None:
        el.text = str(text)
    return el


def _txt(el, tag):
    """Return the stripped text of a child element, or '' if absent."""
    node = el.find(tag)
    return node.text.strip() if node is not None and node.text else ""


def _pretty(root):
    """Serialise an ElementTree root to an indented XML string."""
    raw = ET.tostring(root, encoding="unicode")
    return minidom.parseString(raw).toprettyxml(indent="  ")


# ===========================================================================
#  Role  XML  <->  dict
# ===========================================================================

def role_to_xml(role):
    """Convert a single role dict (API GET response) to an XML element."""
    el = ET.Element("role")
    _sub(el, "extId",       role.get("extId", ""))
    _sub(el, "displayName", role.get("displayName", ""))
    _sub(el, "description", role.get("description", ""))

    # operations: API returns either bare strings or {"extId": ...} dicts
    ops_el = _sub(el, "operations")
    for op in role.get("operations") or []:
        op_el = _sub(ops_el, "operation")
        if isinstance(op, dict):
            _sub(op_el, "extId",       op.get("extId", ""))
            _sub(op_el, "displayName", op.get("displayName", ""))
        else:
            _sub(op_el, "extId",       str(op))
            _sub(op_el, "displayName", "")

    ent_el = _sub(el, "accessibleEntityTypes")
    for ent in role.get("accessibleEntityTypes") or []:
        _sub(ent_el, "entityType",
             ent if isinstance(ent, str) else ent.get("entityType", str(ent)))

    return el


def xml_to_role_payload(el):
    """Convert a <role> XML element to an intermediate dict.

    Note: server-managed fields (roleType etc.) are stripped by
    _strip_role_for_write() before the payload is sent to the API.
    """
    payload = {
        "displayName": _txt(el, "displayName"),
        "description": _txt(el, "description"),
    }
    ops = []
    for op_el in el.findall("operations/operation"):
        eid = op_el.find("extId")
        if eid is not None and eid.text and eid.text.strip():
            ops.append({"extId": eid.text.strip()})
    if ops:
        payload["operations"] = ops

    entity_types = [
        e.text.strip()
        for e in el.findall("accessibleEntityTypes/entityType")
        if e.text
    ]
    if entity_types:
        payload["accessibleEntityTypes"] = entity_types

    return payload


def roles_to_xml_doc(roles, source_pc):
    """Serialise a list of role dicts to a pretty-printed XML string."""
    root = ET.Element("nutanixRolesExport")
    root.set("exportedAt", datetime.now(timezone.utc).isoformat())
    root.set("sourcePC",   source_pc)
    root.set("roleCount",  str(len(roles)))
    root.set("apiVersion", "v4.0")
    _sub(root, "exportNotes", textwrap.dedent("""\
        Generated by nutanix_iam_tool.py  --  roles export.
        Editable fields: displayName, description, operations, accessibleEntityTypes.
        Clear <extId> to force-create instead of update on import.
    """))
    roles_el = _sub(root, "roles")
    for r in roles:
        roles_el.append(role_to_xml(r))
    return _pretty(root)


def xml_doc_to_roles(xml_path):
    """Parse a roles XML file; return list of (extId, payload) tuples."""
    tree = ET.parse(xml_path)
    root = tree.getroot()
    result = []
    for role_el in root.findall("roles/role"):
        eid_el = role_el.find("extId")
        ext_id = eid_el.text.strip() if eid_el is not None and eid_el.text else ""
        result.append((ext_id, xml_to_role_payload(role_el)))
    return result


# ===========================================================================
#  Authorization Policy  XML  <->  dict
# ===========================================================================
#
# The v4.0.b1 API uses an opaque $reserved filter structure for identities
# and entities rather than the typed-object model present in later GA versions.
# Both fields are preserved verbatim as Base64-encoded JSON blobs so that
# round-trips are lossless and no assumptions are made about internal structure.

def _to_b64(obj):
    """Serialise a JSON-serialisable object to a compact Base64 string."""
    return base64.b64encode(
        json.dumps(obj, separators=(",", ":")).encode()
    ).decode()


def _from_b64(s):
    """Deserialise a Base64 string back to a Python object."""
    return json.loads(base64.b64decode(s.encode()).decode())


def _normalise_role_ref(raw):
    """Normalise the role field to a dict regardless of API response shape.

    The API may return role as a bare extId string or as a dict.
    """
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    return {"extId": str(raw), "displayName": ""}


def policy_to_xml(policy):
    """Convert a single authorization-policy dict (API GET response) to XML."""
    el = ET.Element("authorizationPolicy")
    _sub(el, "extId",       policy.get("extId", ""))
    _sub(el, "displayName", policy.get("displayName", ""))
    _sub(el, "description", policy.get("description", ""))
    _sub(el, "policyType",  _policy_type(policy))

    role_ref = _normalise_role_ref(policy.get("role"))
    role_el  = _sub(el, "role")
    _sub(role_el, "extId",       role_ref.get("extId", ""))
    _sub(role_el, "displayName", role_ref.get("displayName", ""))

    # identities: each item serialised as an opaque Base64 JSON blob
    identities_el = _sub(el, "identities")
    for identity in policy.get("identities") or []:
        id_el      = _sub(identities_el, "identity")
        id_el.text = _to_b64(identity)

    # entities: each item serialised as an opaque Base64 JSON blob
    entities_el = _sub(el, "entities")
    for entity in policy.get("entities") or []:
        ent_el      = _sub(entities_el, "entity")
        ent_el.text = _to_b64(entity)

    return el


def _decode_blob(el):
    """Decode a Base64 JSON blob element; return {} on failure."""
    text = el.text.strip() if el.text else ""
    if not text:
        return {}
    try:
        return _from_b64(text)
    except Exception:
        return {}


def xml_to_policy_payload(el):
    """Convert an <authorizationPolicy> XML element to an intermediate dict.

    Note: server-managed fields are stripped by _strip_policy_for_write()
    before the payload is sent to the API.
    """
    payload = {
        "displayName": _txt(el, "displayName"),
        "description": _txt(el, "description"),
        "policyType":  _txt(el, "policyType") or "USER_DEFINED",
    }

    role_el = el.find("role")
    if role_el is not None:
        role_ref = {}
        r_eid   = _txt(role_el, "extId")
        r_dname = _txt(role_el, "displayName")
        if r_eid:   role_ref["extId"]       = r_eid
        if r_dname: role_ref["displayName"] = r_dname
        if role_ref:
            payload["role"] = role_ref

    identities = [
        obj for obj in
        (_decode_blob(id_el) for id_el in el.findall("identities/identity"))
        if obj
    ]
    if identities:
        payload["identities"] = identities

    entities = [
        obj for obj in
        (_decode_blob(ent_el) for ent_el in el.findall("entities/entity"))
        if obj
    ]
    if entities:
        payload["entities"] = entities

    return payload


def policies_to_xml_doc(policies, source_pc):
    """Serialise a list of policy dicts to a pretty-printed XML string."""
    root = ET.Element("nutanixPoliciesExport")
    root.set("exportedAt",  datetime.now(timezone.utc).isoformat())
    root.set("sourcePC",    source_pc)
    root.set("policyCount", str(len(policies)))
    root.set("apiVersion",  "v4.0")
    _sub(root, "exportNotes", textwrap.dedent("""\
        Generated by nutanix_iam_tool.py  --  authorization policies export.

        EDITING GUIDE
        -------------
        <displayName>   Name shown in Prism Central.
        <description>   Free-text purpose / owner notes.
        <policyType>    Should be USER_DEFINED for editable policies.
                        PREDEFINED / SYSTEM policies are exported for
                        reference only and will be skipped on import.

        <role>          The role this policy grants.  Set <extId> to the
                        role's extId on the TARGET Prism Central.  If only
                        <displayName> is given the import will resolve it
                        automatically.

        <identities>    WHO the policy applies to.
                        Each <identity> element contains a Base64-encoded
                        JSON blob preserving the full $reserved filter
                        structure returned by the API. The identity and
                        entity filter format used by this API version is
                        opaque and cannot be hand-edited safely. To change
                        who a policy applies to, update the policy in
                        Prism Central and re-export.

        <entities>      WHAT the policy applies to.
                        Each <entity> element contains a Base64-encoded
                        JSON blob preserving the full $reserved entity
                        filter structure returned by the API. Same
                        editing advice as identities above.

        Clear <extId> on <authorizationPolicy> to force-create on re-import.
    """))

    pols_el = _sub(root, "authorizationPolicies")
    for pol in policies:
        pols_el.append(policy_to_xml(pol))

    return _pretty(root)


def xml_doc_to_policies(xml_path):
    """Parse a policies XML file.

    Returns a list of (extId, payload, policyType) tuples.
    extId is '' when the element was cleared (force-create on import).
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    result = []
    for pol_el in root.findall("authorizationPolicies/authorizationPolicy"):
        eid_el   = pol_el.find("extId")
        ext_id   = eid_el.text.strip() if eid_el is not None and eid_el.text else ""
        payload  = xml_to_policy_payload(pol_el)
        pol_type = payload.get("policyType", "USER_DEFINED")
        result.append((ext_id, payload, pol_type))
    return result


# ===========================================================================
#  Write-safe payload preparation
# ===========================================================================

def _strip_role_for_write(payload):
    """Return a write-safe copy of a role payload for POST / PUT.

    The GET response contains server-managed fields that the API rejects on
    write with HTTP 400:

      roleType, clientName, createdTime, lastUpdatedTime, createdBy,
      accessibleEntityTypesCount, assignedUsersCount, assignedUserGroupsCount,
      isSystemDefined, extId, tenantId, links.

    operations must be a list of bare extId strings, not dicts.
    """
    SERVER_FIELDS = {
        "roleType", "clientName", "createdTime", "lastUpdatedTime",
        "createdBy", "accessibleEntityTypesCount", "assignedUsersCount",
        "assignedUserGroupsCount", "isSystemDefined", "extId", "tenantId", "links",
    }

    write = {k: v for k, v in payload.items() if k not in SERVER_FIELDS}

    # operations: API requires a flat list of bare extId strings
    if "operations" in write:
        clean_ops = []
        for op in write["operations"]:
            eid = op.get("extId", "").strip() if isinstance(op, dict) else str(op).strip()
            if eid:
                clean_ops.append(eid)
        write["operations"] = clean_ops

    return write


def _strip_policy_for_write(payload):
    """Return a write-safe copy of a policy payload for POST / PUT.

    The GET response contains server-managed / read-only fields that the API
    rejects on write with HTTP 400 on v4.0.b1:

      policyType, clientName, createdTime, lastUpdatedTime, isSystemDefined,
      assignedUsersCount, assignedUserGroupsCount, extId, tenantId, links.

    Additionally:
      role           Must be a bare extId string, not a dict.
      identityFilter Read-only mirror inside each identity blob; must be removed.
      entityFilter   Read-only mirror inside each entity blob; must be removed.
    """
    SERVER_FIELDS = {
        "policyType", "clientName", "createdTime", "lastUpdatedTime",
        "isSystemDefined", "assignedUsersCount", "assignedUserGroupsCount",
        "extId", "tenantId", "links",
    }

    write = {k: v for k, v in payload.items() if k not in SERVER_FIELDS}

    # role: API expects a bare extId string
    if "role" in write and isinstance(write["role"], dict):
        write["role"] = write["role"].get("extId", "")

    # identities: strip the read-only identityFilter mirror key
    if "identities" in write:
        write["identities"] = [
            {k: v for k, v in i.items() if k != "identityFilter"}
            if isinstance(i, dict) else i
            for i in write["identities"]
        ]

    # entities: strip the read-only entityFilter mirror key
    if "entities" in write:
        write["entities"] = [
            {k: v for k, v in e.items() if k != "entityFilter"}
            if isinstance(e, dict) else e
            for e in write["entities"]
        ]

    return write


# ===========================================================================
#  Generic create-or-update helper
# ===========================================================================

def _upsert(ext_id, payload, find_by_name_fn, create_fn, update_fn, name):
    """Create or update a single resource.

    Logic:
      - If ext_id is present, attempt update by ID.
        On 404 (resource recreated elsewhere) fall through to create.
      - If ext_id is absent, look up by display name.
        Update if found, otherwise create.

    Returns (action, ext_id) where action is 'created' or 'updated'.
    """
    if ext_id:
        try:
            update_fn(ext_id, payload)
            return ("updated", ext_id)
        except RuntimeError as exc:
            if "404" not in str(exc):
                raise
            # extId no longer valid -- fall through to create
    else:
        existing = find_by_name_fn(name)
        if existing:
            eid = existing["extId"]
            update_fn(eid, payload)
            return ("updated", eid)

    resp   = create_fn(payload)
    new_id = (resp.get("data") or {}).get("extId", "?")
    return ("created", new_id)


# ===========================================================================
#  Shared client factory
# ===========================================================================

def _make_client(args):
    return PrismClient(
        host              = args.pc,
        username          = args.user,
        password          = args.password,
        port              = args.port,
        verify_ssl        = args.verify_ssl,
        roles_api_base    = getattr(args, "roles_api_base",    None),
        policies_api_base = getattr(args, "policies_api_base", None),
    )


# ===========================================================================
#  Role commands
# ===========================================================================

def cmd_export_roles(args):
    client = _make_client(args)
    print("[+] Connecting to {}:{} ...".format(args.pc, args.port))
    all_roles = client.list_roles()
    print("    {} total role(s) found.".format(len(all_roles)))

    if args.names:
        names   = set(args.names)
        matched = [r for r in all_roles if r.get("displayName") in names]
        missing = names - {r.get("displayName") for r in matched}
        if missing:
            print("[!] WARNING: role(s) not found: {}".format(
                ", ".join(sorted(missing))))
        roles = matched
    else:
        roles = all_roles

    if not roles:
        print("[!] No roles to export.  Exiting.")
        sys.exit(1)

    print("[+] Exporting {} role(s):".format(len(roles)))
    for r in roles:
        print("    * {!r}  extId={}  ops={}".format(
            r.get("displayName"), r.get("extId"),
            len(r.get("operations") or [])))

    out = args.out or "nutanix_roles_{}.xml".format(
        datetime.now().strftime("%Y%m%d_%H%M%S"))
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(roles_to_xml_doc(roles, args.pc))
    print("\n[OK] Roles exported to: {}".format(out))
    return out


def cmd_import_roles(args):
    print("[+] Parsing roles XML: {}".format(args.in_))
    try:
        entries = xml_doc_to_roles(args.in_)
    except ET.ParseError as exc:
        print("[ERR] XML parse error: {}".format(exc))
        sys.exit(1)

    if not entries:
        print("[!] No roles found in XML.  Exiting.")
        sys.exit(1)
    print("    {} role(s) found.".format(len(entries)))

    if args.dry_run:
        print("\n[DRY RUN] Roles that would be created/updated:\n")
        for ext_id, payload in entries:
            print("  [{}] {!r}  extId={}  ops={}".format(
                "UPDATE" if ext_id else "CREATE",
                payload.get("displayName"),
                ext_id or "<new>",
                len(payload.get("operations", []))))
        print("\n[DRY RUN] No changes made.")
        return

    client  = _make_client(args)
    print("[+] Connecting to {}:{} ...".format(args.pc, args.port))
    created = updated = failed = 0

    for ext_id, payload in entries:
        name = payload.get("displayName", "<unnamed>")
        try:
            write_payload = _strip_role_for_write(payload)
            action, new_id = _upsert(
                ext_id, write_payload,
                client.find_role_by_name,
                client.create_role,
                client.update_role,
                name,
            )
            print("  [{}] {!r}  extId={}".format(
                "CREATED" if action == "created" else "UPDATED", name, new_id))
            if action == "created": created += 1
            else:                   updated += 1
        except RuntimeError as exc:
            print("  [FAILED]  {!r}: {}".format(name, exc))
            failed += 1

    print("\n[OK] Roles import complete -- created: {}, updated: {}, failed: {}".format(
        created, updated, failed))
    if failed:
        sys.exit(1)


# ===========================================================================
#  Policy commands
# ===========================================================================


def _policy_type(p):
    """Return the policy type from either the GA or beta API field name."""
    return p.get("policyType") or p.get("authorizationPolicyType") or "USER_DEFINED"

_SYSTEM_POLICY_TYPES = {"PREDEFINED", "SYSTEM", "BUILT_IN"}


def cmd_export_policies(args):
    client = _make_client(args)
    print("[+] Connecting to {}:{} ...".format(args.pc, args.port))
    print("    Policies API base: {}".format(client.policies_base))
    all_policies = client.list_policies()
    print("    {} total authorization polic(ies) found.".format(len(all_policies)))

    if args.names:
        names   = set(args.names)
        matched = [p for p in all_policies if p.get("displayName") in names]
        missing = names - {p.get("displayName") for p in matched}
        if missing:
            print("[!] WARNING: polic(ies) not found: {}".format(
                ", ".join(sorted(missing))))
        policies = matched
    else:
        policies = all_policies

    if not policies:
        print("[!] No policies to export.  Exiting.")
        sys.exit(1)

    system_count = sum(
        1 for p in policies if _policy_type(p) in _SYSTEM_POLICY_TYPES
    )
    if system_count:
        print("[!] NOTE: {} system/predefined polic(ies) included "
              "(exported for reference; will be skipped on import).".format(
                  system_count))

    print("[+] Exporting {} authorization polic(ies):".format(len(policies)))
    for p in policies:
        rr        = _normalise_role_ref(p.get("role"))
        role_name = rr.get("displayName") or rr.get("extId") or "-"
        print("    * {!r}  extId={}  type={}  role={!r}  "
              "identities={}  entities={}".format(
                  p.get("displayName"), p.get("extId"), _policy_type(p),
                  role_name,
                  len(p.get("identities") or []),
                  len(p.get("entities") or [])))

    out = args.out or "nutanix_policies_{}.xml".format(
        datetime.now().strftime("%Y%m%d_%H%M%S"))
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(policies_to_xml_doc(policies, args.pc))
    print("\n[OK] Policies exported to: {}".format(out))
    return out


def _resolve_role_ref(client, role_ref):
    """Resolve a role reference to {extId, displayName} on the target PC.

    Accepts either a bare string extId or a dict with extId/displayName.
    If extId is missing, falls back to name lookup.
    Returns None if the role cannot be found.
    """
    role_ref = _normalise_role_ref(role_ref)
    if role_ref.get("extId"):
        return role_ref
    name = role_ref.get("displayName", "")
    if not name:
        return None
    found = client.find_role_by_name(name)
    if found:
        return {"extId": found["extId"], "displayName": found["displayName"]}
    return None


def cmd_import_policies(args):
    print("[+] Parsing policies XML: {}".format(args.in_))
    try:
        entries = xml_doc_to_policies(args.in_)
    except ET.ParseError as exc:
        print("[ERR] XML parse error: {}".format(exc))
        sys.exit(1)

    if not entries:
        print("[!] No policies found in XML.  Exiting.")
        sys.exit(1)
    print("    {} polic(ies) found.".format(len(entries)))

    user_entries = [
        (eid, pay, pt) for eid, pay, pt in entries
        if pt not in _SYSTEM_POLICY_TYPES
    ]
    skipped = len(entries) - len(user_entries)
    if skipped:
        print("[!] Skipping {} system/predefined polic(ies) "
              "(cannot be imported).".format(skipped))

    if args.dry_run:
        print("\n[DRY RUN] Policies that would be created/updated:\n")
        for ext_id, payload, _ in user_entries:
            rr        = _normalise_role_ref(payload.get("role"))
            role_info = rr.get("displayName") or rr.get("extId") or "-"
            print("  [{}] {!r}  extId={}  role={!r}  "
                  "identities={}  entities={}".format(
                      "UPDATE" if ext_id else "CREATE",
                      payload.get("displayName"), ext_id or "<new>",
                      role_info,
                      len(payload.get("identities", [])),
                      len(payload.get("entities", []))))
        print("\n[DRY RUN] No changes made.")
        return

    client  = _make_client(args)
    print("[+] Connecting to {}:{} ...".format(args.pc, args.port))
    print("    Policies API base: {}".format(client.policies_base))
    created = updated = failed = 0

    for ext_id, payload, _ in user_entries:
        name = payload.get("displayName", "<unnamed>")
        try:
            raw_role = payload.get("role")
            if raw_role:
                resolved = _resolve_role_ref(client, raw_role)
                if resolved:
                    payload["role"] = resolved
                else:
                    raise RuntimeError(
                        "Cannot resolve role {!r} on target PC "
                        "-- import roles first.".format(
                            _normalise_role_ref(raw_role).get("displayName")
                            or _normalise_role_ref(raw_role).get("extId"))
                    )

            write_payload = _strip_policy_for_write(payload)
            action, new_id = _upsert(
                ext_id, write_payload,
                client.find_policy_by_name,
                client.create_policy,
                client.update_policy,
                name,
            )
            print("  [{}] {!r}  extId={}".format(
                "CREATED" if action == "created" else "UPDATED", name, new_id))
            if action == "created": created += 1
            else:                   updated += 1

        except RuntimeError as exc:
            print("  [FAILED]  {!r}: {}".format(name, exc))
            failed += 1

    print("\n[OK] Policies import complete -- created: {}, updated: {}, failed: {}".format(
        created, updated, failed))
    if failed:
        sys.exit(1)


# ===========================================================================
#  export-all command
# ===========================================================================

def cmd_export_all(args):
    """Export both roles and authorization policies in a single pass."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    class _Args(object):
        def __init__(self, base, **overrides):
            self.__dict__.update(vars(base))
            self.__dict__.update(overrides)

    roles_args = _Args(
        args,
        names=None,
        out=args.roles_out or "nutanix_roles_{}.xml".format(ts),
    )
    policies_args = _Args(
        args,
        names=None,
        out=args.policies_out or "nutanix_policies_{}.xml".format(ts),
    )

    print("=" * 60)
    print("  EXPORTING ROLES")
    print("=" * 60)
    cmd_export_roles(roles_args)

    print()
    print("=" * 60)
    print("  EXPORTING AUTHORIZATION POLICIES")
    print("=" * 60)
    cmd_export_policies(policies_args)


# ===========================================================================
#  CLI parser
# ===========================================================================

def build_parser():
    p = argparse.ArgumentParser(
        prog="nutanix_iam_tool.py",
        description=(
            "Export / import Nutanix Prism Central roles and "
            "authorization policies to/from human-readable XML."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Subcommands:
              export-roles      Export named (or all) roles
              import-roles      Restore roles from XML
              export-policies   Export named (or all) authorization policies
              import-policies   Restore authorization policies from XML
              export-all        Export both roles and policies in one pass

            Add --dry-run to any import command to preview without changes.

            Policy API path override (if your PC uses the GA path):
              --policies-api-base api/iam/v4.0/authz   (for pc.2024.3+)

            See README.md for full documentation.
        """),
    )

    # -- shared connection parent --------------------------------------------
    conn = argparse.ArgumentParser(add_help=False)
    conn.add_argument("--pc",       required=True,
                      help="Prism Central hostname or IP")
    conn.add_argument("--port",     type=int, default=9440,
                      help="HTTPS port (default: 9440)")
    conn.add_argument("--user",     required=True,
                      help="Prism Central username")
    conn.add_argument("--password", default=None,
                      help="Password (secure prompt if omitted)")
    conn.add_argument("--verify-ssl", action="store_true", default=False,
                      dest="verify_ssl",
                      help="Verify TLS certificate (default: off for lab certs)")
    conn.add_argument("--roles-api-base", default=None,
                      dest="roles_api_base",
                      help="Override roles API base path "
                           "(default: api/iam/v4.0/authz)")
    conn.add_argument("--policies-api-base", default=None,
                      dest="policies_api_base",
                      help="Override policies API base path "
                           "(default: api/iam/v4.0.b1/authz). "
                           "Use api/iam/v4.0/authz for pc.2024.3+")

    sub = p.add_subparsers(dest="command", required=True)

    # -- export-roles --------------------------------------------------------
    er = sub.add_parser("export-roles", parents=[conn],
                        help="Export roles to XML")
    er.add_argument("--names", nargs="*", metavar="NAME",
                    help="Role display names to export (omit = all)")
    er.add_argument("--out", metavar="FILE",
                    help="Output XML path (auto-named if omitted)")

    # -- import-roles --------------------------------------------------------
    ir = sub.add_parser("import-roles", parents=[conn],
                        help="Import roles from XML")
    ir.add_argument("--in", required=True, metavar="FILE",
                    dest="in_",
                    help="Input XML file to import")
    ir.add_argument("--dry-run", action="store_true",
                    help="Preview without making changes")

    # -- export-policies -----------------------------------------------------
    ep = sub.add_parser("export-policies", parents=[conn],
                        help="Export authorization policies to XML")
    ep.add_argument("--names", nargs="*", metavar="NAME",
                    help="Policy display names to export (omit = all)")
    ep.add_argument("--out", metavar="FILE",
                    help="Output XML path (auto-named if omitted)")

    # -- import-policies -----------------------------------------------------
    imp = sub.add_parser("import-policies", parents=[conn],
                         help="Import authorization policies from XML")
    imp.add_argument("--in", required=True, metavar="FILE",
                     dest="in_",
                     help="Input XML file to import")
    imp.add_argument("--dry-run", action="store_true",
                     help="Preview without making changes")

    # -- export-all ----------------------------------------------------------
    ea = sub.add_parser("export-all", parents=[conn],
                        help="Export both roles and policies in one pass")
    ea.add_argument("--roles-out",    metavar="FILE", default=None,
                    help="Output XML for roles (auto-named if omitted)")
    ea.add_argument("--policies-out", metavar="FILE", default=None,
                    help="Output XML for policies (auto-named if omitted)")

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not args.password:
        args.password = getpass.getpass(
            "Password for {}@{}: ".format(args.user, args.pc)
        )

    dispatch = {
        "export-roles":     cmd_export_roles,
        "import-roles":     cmd_import_roles,
        "export-policies":  cmd_export_policies,
        "import-policies":  cmd_import_policies,
        "export-all":       cmd_export_all,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
