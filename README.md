# nutanix_iam_tool

Export and import Nutanix Prism Central **roles** and **authorization policies**
to and from human-readable, editable XML files using the Prism Central v4 IAM API.

Typical use cases:

- Back up IAM configuration before a Prism Central upgrade or migration
- Replicate a role/policy set from one Prism Central instance to another
- Keep IAM definitions in version control alongside infrastructure-as-code
- Audit and peer-review access policies in a readable format before applying them


## Requirements

- Python 3.7 or later
- The `requests` library: `pip install requests`
- A Prism Central account with sufficient privileges to read and write IAM objects
  (the built-in **Prism Central Admin** role is sufficient; a custom role needs at
  minimum View, Create, and Update permissions on Roles and Authorization Policies)


## Files

```
nutanix_iam_tool.py   ← the tool
README.md             ← this file
```


## Quick start

```bash
# Export all roles
python nutanix_iam_tool.py export-roles --pc 10.0.0.1 --user admin --out roles.xml

# Export all authorization policies
python nutanix_iam_tool.py export-policies --pc 10.0.0.1 --user admin --out policies.xml

# Export both in one command
python nutanix_iam_tool.py export-all \
    --pc 10.0.0.1 --user admin \
    --roles-out roles.xml --policies-out policies.xml

# Dry-run an import (validate and preview without making any changes)
python nutanix_iam_tool.py import-roles \
    --pc 10.0.0.2 --user admin --in roles.xml --dry-run

# Live import
python nutanix_iam_tool.py import-roles \
    --pc 10.0.0.2 --user admin --in roles.xml
```

If `--password` is omitted the tool prompts for it securely so that credentials
are never exposed in shell history.


---


## Subcommands

### `export-roles`

Connects to Prism Central and writes one or more roles to an XML file.

```
python nutanix_iam_tool.py export-roles [OPTIONS]
```

| Option | Required | Description |
|---|---|---|
| `--pc HOST` | Yes | Prism Central hostname or IP address |
| `--port PORT` | No | HTTPS port (default: `9440`) |
| `--user USER` | Yes | Prism Central username |
| `--password PASS` | No | Password (prompted if omitted) |
| `--names NAME ...` | No | Role display names to export. Omit to export **all** roles |
| `--out FILE` | No | Output XML path (auto-named with timestamp if omitted) |
| `--verify-ssl` | No | Verify the TLS certificate. Off by default for lab/self-signed certs |
| `--roles-api-base PATH` | No | Override the roles API base path (see API version notes) |

Examples:

```bash
# Export two specific roles
python nutanix_iam_tool.py export-roles \
    --pc 10.0.0.1 --user admin \
    --names "DB Admin" "Network Viewer" \
    --out roles_backup.xml

# Export every role
python nutanix_iam_tool.py export-roles --pc 10.0.0.1 --user admin --out all_roles.xml
```


### `import-roles`

Reads roles from an XML file and creates or updates them on Prism Central.

```
python nutanix_iam_tool.py import-roles [OPTIONS]
```

| Option | Required | Description |
|---|---|---|
| `--pc HOST` | Yes | Target Prism Central hostname or IP |
| `--port PORT` | No | HTTPS port (default: `9440`) |
| `--user USER` | Yes | Prism Central username |
| `--password PASS` | No | Password (prompted if omitted) |
| `--in FILE` | Yes | Input XML file to import |
| `--dry-run` | No | Parse and preview actions without making any API calls |
| `--verify-ssl` | No | Verify the TLS certificate |
| `--roles-api-base PATH` | No | Override the roles API base path |

**Import logic:**

1. If `<extId>` is present and non-empty, the tool attempts to **update** the existing role by that ID. If the ID is not found (e.g. after a recreation), it falls back to **create**.
2. If `<extId>` is empty, the tool searches for an existing role with the same `<displayName>`. If found it **updates**; otherwise it **creates**.

Always run with `--dry-run` first when importing to a production system.

```bash
python nutanix_iam_tool.py import-roles \
    --pc 10.0.0.2 --user admin --in roles_backup.xml --dry-run

python nutanix_iam_tool.py import-roles \
    --pc 10.0.0.2 --user admin --in roles_backup.xml
```


### `export-policies`

Connects to Prism Central and writes one or more authorization policies to an XML file.
System and predefined policies are included in the export for reference but are flagged
with a warning — they cannot be re-imported.

```
python nutanix_iam_tool.py export-policies [OPTIONS]
```

| Option | Required | Description |
|---|---|---|
| `--pc HOST` | Yes | Prism Central hostname or IP address |
| `--port PORT` | No | HTTPS port (default: `9440`) |
| `--user USER` | Yes | Prism Central username |
| `--password PASS` | No | Password (prompted if omitted) |
| `--names NAME ...` | No | Policy display names to export. Omit to export **all** |
| `--out FILE` | No | Output XML path (auto-named with timestamp if omitted) |
| `--verify-ssl` | No | Verify the TLS certificate |
| `--policies-api-base PATH` | No | Override the policies API base path (see API version notes) |

```bash
# Export two specific policies
python nutanix_iam_tool.py export-policies \
    --pc 10.0.0.1 --user admin \
    --names "Prod VM Owners" "Read-Only Auditors" \
    --out policies_backup.xml

# Export everything
python nutanix_iam_tool.py export-policies --pc 10.0.0.1 --user admin --out all_policies.xml
```


### `import-policies`

Reads authorization policies from an XML file and creates or updates them on
Prism Central. System and predefined policies in the file are automatically skipped.

```
python nutanix_iam_tool.py import-policies [OPTIONS]
```

| Option | Required | Description |
|---|---|---|
| `--pc HOST` | Yes | Target Prism Central hostname or IP |
| `--port PORT` | No | HTTPS port (default: `9440`) |
| `--user USER` | Yes | Prism Central username |
| `--password PASS` | No | Password (prompted if omitted) |
| `--in FILE` | Yes | Input XML file to import |
| `--dry-run` | No | Parse and preview actions without making any API calls |
| `--verify-ssl` | No | Verify the TLS certificate |
| `--policies-api-base PATH` | No | Override the policies API base path |

**Import logic:**

The same create-or-update rules from `import-roles` apply. Additionally:

- The **role reference** inside each policy is resolved before the API call. If
  `<role><extId>` is present it is used directly. If it is blank or stale, the tool
  resolves the role by `<displayName>` on the target PC. If the role cannot be found
  the policy import fails with a clear error — import the roles first.
- Policies with `<policyType>` set to `PREDEFINED`, `SYSTEM`, or `BUILT_IN` are
  silently skipped regardless of other settings.

**Order of operations when migrating to a new Prism Central:**

1. Export roles from the source PC
2. Export policies from the source PC
3. Import roles to the target PC **first**
4. Import policies to the target PC **second**

```bash
python nutanix_iam_tool.py import-policies \
    --pc 10.0.0.2 --user admin --in policies_backup.xml --dry-run

python nutanix_iam_tool.py import-policies \
    --pc 10.0.0.2 --user admin --in policies_backup.xml
```


### `export-all`

Convenience command that runs `export-roles` and `export-policies` in a single
pass against the same Prism Central, producing two separate XML files.

```
python nutanix_iam_tool.py export-all [OPTIONS]
```

| Option | Required | Description |
|---|---|---|
| `--pc HOST` | Yes | Prism Central hostname or IP address |
| `--port PORT` | No | HTTPS port (default: `9440`) |
| `--user USER` | Yes | Prism Central username |
| `--password PASS` | No | Password (prompted if omitted) |
| `--roles-out FILE` | No | Output path for roles XML (auto-named if omitted) |
| `--policies-out FILE` | No | Output path for policies XML (auto-named if omitted) |
| `--verify-ssl` | No | Verify the TLS certificate |
| `--roles-api-base PATH` | No | Override the roles API base path |
| `--policies-api-base PATH` | No | Override the policies API base path |

```bash
python nutanix_iam_tool.py export-all \
    --pc 10.0.0.1 --user admin \
    --roles-out roles.xml \
    --policies-out policies.xml
```


---


## API version notes

Roles and authorization policies live under different API version prefixes
depending on your Prism Central release:

| Resource | Default path used by this tool | GA path (pc.2024.3+) |
|---|---|---|
| Roles | `api/iam/v4.0/authz/roles` | same |
| Policies | `api/iam/v4.0.b1/authz/authorization-policies` | `api/iam/v4.0/authz/authorization-policies` |

The tool defaults to the beta path for policies (`v4.0.b1`), which is correct for
Prism Central versions prior to the IAM GA release. If your PC is on pc.2024.3 or
later, pass `--policies-api-base api/iam/v4.0/authz` to any policy subcommand
or to `export-all`.

The active policies base path is printed at the start of every policy operation
so you can confirm which version is in use.


---


## XML file format

Both file types are designed to be readable and editable in any text editor.
An `<exportNotes>` element at the top of each file summarises what can safely
be edited.


### Roles XML

```xml
<nutanixRolesExport exportedAt="..." sourcePC="..." roleCount="1" apiVersion="v4.0">
  <roles>
    <role>
      <extId>aaaabbbb-1111-2222-3333-ccccddddeeee</extId>
      <displayName>DB Admin</displayName>
      <description>Full VM lifecycle access for database workloads.</description>
      <operations>
        <operation>
          <extId>op-vm-create-uuid</extId>
          <displayName>Create VM</displayName>
        </operation>
      </operations>
      <accessibleEntityTypes>
        <entityType>VM</entityType>
      </accessibleEntityTypes>
    </role>
  </roles>
</nutanixRolesExport>
```

| Element | Editable | Notes |
|---|---|---|
| `<extId>` on `<role>` | Yes | Clear to force-create on import instead of updating |
| `<displayName>` | Yes | Name shown in Prism Central |
| `<description>` | Yes | Free-text; supports line breaks |
| `<operations>` | Yes | Add or remove `<operation>` blocks; each needs `<extId>` |
| `<accessibleEntityTypes>` | Yes | Scope the role to specific entity types |

`<displayName>` inside `<operation>` is informational only and is ignored on import.


### Policies XML

```xml
<nutanixPoliciesExport exportedAt="..." sourcePC="..." policyCount="1" apiVersion="v4.0">
  <authorizationPolicies>
    <authorizationPolicy>
      <extId>pol-aaaa-...</extId>
      <displayName>DBA Team — Production VMs</displayName>
      <description>Grants DB Admin to the DBA group on Production VMs.</description>
      <policyType>USER_DEFINED</policyType>
      <role>
        <extId>aaaabbbb-1111-...</extId>
        <displayName>DB Admin</displayName>
      </role>
      <identities>
        <identity>eyIkcmVzZXJ2ZWQi...</identity>
      </identities>
      <entities>
        <entity>eyIkcmVzZXJ2ZWQi...</entity>
      </entities>
    </authorizationPolicy>
  </authorizationPolicies>
</nutanixPoliciesExport>
```

| Element | Editable | Notes |
|---|---|---|
| `<extId>` on `<authorizationPolicy>` | Yes | Clear to force-create on import |
| `<displayName>` | Yes | Name shown in Prism Central |
| `<description>` | Yes | Free-text |
| `<role><extId>` | Yes | Role extId on the **target** PC. If blank, resolved by `<displayName>` |
| `<identities>` / `<entities>` | **No** | Base64-encoded opaque API blobs — see below |

**Identity and entity blobs:** The v4.0.b1 API uses an internal `$reserved` filter
structure for identities and entities that has no stable field mapping. Each
`<identity>` and `<entity>` element stores the complete API object as a Base64-encoded
JSON blob. These blobs must not be hand-edited. To change who a policy applies to or
what it scopes to, update the policy in Prism Central and re-export.


---


## Common workflows

### Back up before an upgrade

```bash
python nutanix_iam_tool.py export-all \
    --pc prism.example.local --user admin \
    --roles-out backup/roles_pre_upgrade.xml \
    --policies-out backup/policies_pre_upgrade.xml
```

### Migrate IAM to a new Prism Central

```bash
# 1. Export from source
python nutanix_iam_tool.py export-all \
    --pc source-pc.example.local --user admin \
    --roles-out roles.xml --policies-out policies.xml

# 2. Dry-run against target to check for issues
python nutanix_iam_tool.py import-roles \
    --pc target-pc.example.local --user admin --in roles.xml --dry-run
python nutanix_iam_tool.py import-policies \
    --pc target-pc.example.local --user admin --in policies.xml --dry-run

# 3. Apply — roles must be imported before policies
python nutanix_iam_tool.py import-roles \
    --pc target-pc.example.local --user admin --in roles.xml
python nutanix_iam_tool.py import-policies \
    --pc target-pc.example.local --user admin --in policies.xml
```

### Clone a role and create a variant

1. Export the role you want to clone:
   ```bash
   python nutanix_iam_tool.py export-roles \
       --pc 10.0.0.1 --user admin --names "DB Admin" --out db_admin.xml
   ```
2. Open `db_admin.xml` in a text editor.
3. Clear the `<extId>` element (leave it empty).
4. Change `<displayName>` to the new name.
5. Add or remove `<operation>` blocks as needed.
6. Import — the empty `<extId>` forces a create:
   ```bash
   python nutanix_iam_tool.py import-roles \
       --pc 10.0.0.1 --user admin --in db_admin.xml
   ```

### Store IAM in version control

```bash
python nutanix_iam_tool.py export-all \
    --pc prism.example.local --user "$PC_USER" --password "$PC_PASS" \
    --roles-out iam/roles.xml --policies-out iam/policies.xml

git -C iam add roles.xml policies.xml
git -C iam commit -m "IAM snapshot $(date -u +%Y-%m-%dT%H:%M:%SZ)"
git -C iam push
```


---


## Troubleshooting

**`HTTP 401` on every request**
Verify username and password. Prism Central usernames are case-sensitive.

**`HTTP 403` on create/update but not on list**
The authenticated user has read-only access. Assign a role that includes Create
and Update permissions for Roles and/or Authorization Policies.

**`HTTP 404` on policy endpoints**
Your Prism Central is likely pre-GA for the IAM API. Verify the policies base path
printed at startup. If it shows `v4.0.b1` but fails, try the GA path:
```bash
--policies-api-base api/iam/v4.0/authz
```

**`HTTP 428` on update (Precondition Required)**
The v4 API requires optimistic concurrency control on all PUT requests. The tool
handles this automatically by performing a GET before every PUT to retrieve the
current `ETag`, then supplying it as the `If-Match` header. If you see this error
it most likely means the GET itself failed — check connectivity and credentials.

**`HTTP 400` on import with schema validation errors**
The tool strips all known read-only fields before sending to the API. If you see
new `unsupported property` errors on a different PC version, note the field names
from the error and report them — the `SERVER_FIELDS` sets in `_strip_role_for_write`
and `_strip_policy_for_write` can be extended without other code changes.

**`SSL: CERTIFICATE_VERIFY_FAILED`**
Add `--verify-ssl` if you have a valid trusted certificate, or omit it (the
default) to skip verification for self-signed lab certificates.

**`[FAILED] "My Policy": Cannot resolve role "My Role" on target PC`**
The role referenced by the policy does not exist on the target PC yet.
Run `import-roles` first, then re-run `import-policies`.

**Policy skipped with "system/predefined" warning**
Policies with `<policyType>` of `PREDEFINED`, `SYSTEM`, or `BUILT_IN` are managed
by Nutanix and cannot be created or replaced via the API. This is expected.


---


## Security notes

- Credentials entered at the password prompt are not echoed and are not written
  to any file.
- Supplying `--password` on the command line exposes the value in the process list.
  Prefer the interactive prompt, or pass the value via an environment variable
  through your secrets manager.
- Exported XML files contain UUIDs of directory objects (users, groups). Treat them
  with the same care as any infrastructure configuration file.
- TLS certificate verification is off by default to accommodate self-signed
  certificates common in Nutanix lab environments. Enable `--verify-ssl` in
  production environments where a trusted certificate is in place.


---


## API reference

This tool uses the Nutanix Prism Central v4 IAM API:

| Resource | Endpoint |
|---|---|
| Roles | `https://<PC>:9440/api/iam/v4.0/authz/roles` |
| Authorization Policies (pre-GA) | `https://<PC>:9440/api/iam/v4.0.b1/authz/authorization-policies` |
| Authorization Policies (pc.2024.3+) | `https://<PC>:9440/api/iam/v4.0/authz/authorization-policies` |

Full API documentation is available at `https://developers.nutanix.com`.
