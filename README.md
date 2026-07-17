# salt-windows

Salt execution modules and states for administering Windows systems, maintained by [Alkivi](https://www.alkivi.fr).

These modules cover ground the official `win_*` catalogue does not: BitLocker volume state, Azure AD account reconciliation, hotfix history with release dates, IIS management, workstation provisioning, and a declarative layer over the Windows Firewall.

All modules are Windows-only — `__virtual__` returns `False` on any other platform, so they are safe to sync to a mixed fleet.

## Layout

```
modules/    execution modules  -> deploy as _modules/
states/     state modules      -> deploy as _states/
```

Directories are deliberately named without the leading underscore so the repository can be vendored as a submodule and symlinked into a Salt fileserver root (see Installation).

## Modules

Note that the **file name is not the invocation name**: each module declares a `__virtualname__`, and that is what you call.

| File | Call it as | Purpose |
| :--- | :--- | :--- |
| `modules/alkivi_win_firewall.py` | `alkivi_win_firewall` | Windows Firewall rules and profiles, via PowerShell/NetSecurity |
| `modules/win_bitlocker.py` | `bitlocker` | BitLocker volume status and recovery key handling |
| `modules/win_azuread.py` | `azuread` | Reconcile an Azure AD account export against pillar users |
| `modules/win_updates.py` | `win_updates` | Installed hotfix history, enriched with release dates |
| `modules/win_iis.py` | `win_iis` | IIS sites and application pools |
| `modules/win_install.py` | `install` | Windows workstation provisioning |
| `modules/win_collect.py` | `collect` | Drive letters to include in backups |
| `states/win_firewall_rule.py` | `win_firewall_rule` | Declarative Windows Firewall rules |

## Requirements

- A Windows minion.
- PowerShell. Most modules shell out to it; `bitlocker` checks for it explicitly in `__virtual__` and refuses to load otherwise.
- The `NetSecurity` module (ships with Windows 8/2012 and later) for the `alkivi_win_firewall.ps_*` functions and the `win_firewall_rule` state.
- `win_updates.history` needs outbound HTTPS to `support.microsoft.com` (see Limitations).

## Installation

### As a submodule with symlinks

This is how the repository is consumed in Alkivi's Salt tree, and why `modules/` and `states/` carry no underscore:

```bash
git submodule add git@github.com:alkivi-sas/salt-windows.git github/salt-windows

ln -s ../github/salt-windows/modules/win_bitlocker.py _modules/win_bitlocker.py
ln -s ../github/salt-windows/states/win_firewall_rule.py _states/win_firewall_rule.py
# ... one symlink per module you want to expose
```

Symlinking per file lets each Salt tree expose only the modules it needs.

### By copying

```bash
cp modules/*.py /srv/salt/_modules/
cp states/*.py  /srv/salt/_states/
```

Either way, sync to the minions:

```bash
salt 'win-*' saltutil.sync_all
```

## Usage

### `alkivi_win_firewall`

Two generations of functions coexist. The `ps_*` functions drive PowerShell/NetSecurity cmdlets and are the ones to use. The older `add_rule` / `add_ping_rule` shell out to `netsh` and are kept for backwards compatibility with existing states.

```bash
# Profiles (Domain / Private / Public)
salt 'win-*' alkivi_win_firewall.get_config

# List rules
salt 'win-*' alkivi_win_firewall.ps_get_rules
salt 'win-*' alkivi_win_firewall.ps_get_rules enabled=True direction=outgoing
salt 'win-*' alkivi_win_firewall.ps_get_rule display_name='My Rule'

# Create, modify, delete
salt 'win-*' alkivi_win_firewall.ps_add_rule 'HTTP' direction=Inbound protocol=TCP local_port=80
salt 'win-*' alkivi_win_firewall.ps_set_rule display_name='HTTP' enabled=False
salt 'win-*' alkivi_win_firewall.ps_del_rule display_name='Old rule'

# Bulk delete by substring — wildcards are escaped and matched literally
salt 'win-*' alkivi_win_firewall.ps_del_rule display_name_contains='(mDNS-In)'
```

`ps_del_rule` returns the list of rules it deleted (`Name`, `DisplayName`, `DisplayGroup`, `Group`), or an empty list when nothing matched.

### `win_firewall_rule` (state)

Rules are identified by `DisplayName`. **Only the parameters you actually declare are compared and updated** — anything you leave out is preserved on an existing rule. Defaults apply solely at creation time.

```yaml
allow_http:
  win_firewall_rule.present:
    - name: HTTP
    - direction: Inbound
    - protocol: TCP
    - local_port: 80
    - action: Allow

sip_ports:
  win_firewall_rule.present:
    - name: SIP
    - protocol: UDP
    - local_port:
        - 5060
        - "40000-60000"
    - remote_address:
        - 192.168.0.0/24
        - 10.0.0.0/8

remove_legacy_rule:
  win_firewall_rule.absent:
    - name: OldRuleName
```

Values are normalised before comparison, so the state stays idempotent across cosmetic differences:

- Port and address lists compare as unordered sets — YAML order does not matter.
- A scalar and a single-element list are equivalent.
- Subnets are canonicalised, so `51.83.58.98/28` and `51.83.58.96/255.255.255.240` are recognised as the same network and do not produce perpetual changes.

`test=True` is supported and reports which keys would change.

### `bitlocker`

```bash
salt 'win-*' bitlocker.get_status
salt 'win-*' bitlocker.get_status 'D:'
salt 'win-*' bitlocker.get_recovery_key
salt 'win-*' bitlocker.resume_protection
```

`sync_recovery_key` reads the recovery password and publishes it on the Salt event bus as `alkivi/password/set`, rather than writing to a directory from the minion. The minion therefore needs no directory credentials; archiving is the master's responsibility, via a reactor bound to that event.

```bash
salt 'win-*' bitlocker.sync_recovery_key
```

Recovery keys are sensitive. `get_recovery_key` returns one in cleartext to the caller, and `sync_recovery_key` puts one on the event bus — restrict who can run these and who can subscribe to the bus.

### `win_updates`

```bash
salt 'win-*' win_updates.history
```

Returns installed hotfixes (`HotFixID`, `Description`, `InstalledOn`) from `Get-Hotfix`, each enriched with the `ReleaseDate` scraped from its KB page — which is what lets you reason about patch lag rather than just presence.

### `azuread`

```bash
salt 'win-*' azuread.matches 'C:\path\to\accounts.xml'
```

Parses an XML export of Azure AD accounts and matches it against the `users` pillar by display name, returning `SourceAccount` / `TargetAccount` pairs. Accounts whose display name contains `alkivi`, and UPNs containing `package`, are skipped. Working from an export rather than Microsoft Graph keeps token handling out of the minion.

### `win_iis`

```bash
salt 'win-*' win_iis.list_sites
salt 'win-*' win_iis.create_site name='MySite' protocol='http' sourcepath='C:\inetpub\mysite' port=80
salt 'win-*' win_iis.remove_site 'MySite'

salt 'win-*' win_iis.list_apppools
salt 'win-*' win_iis.create_apppool 'MyPool'
salt 'win-*' win_iis.remove_apppool 'MyPool'
```

### `install`

Workstation provisioning helpers, each covering one step of an Alkivi Windows build: `users`, `system`, `clean_mcafee`, `clean_dell`, `openvpn`, `firewall`, `zabbix`, `backup`, `ninite`, `office365`, `network_credentials`.

These are opinionated and tailored to Alkivi's build — read the function before running it, and expect to adapt it to your own environment.

### `collect`

```bash
salt 'win-*' collect.disks
```

## Limitations

- **`bitlocker` is read-mostly.** It reports status, retrieves the recovery key and resumes protection. It does not enable encryption or rotate keys.
- **PowerShell enums do not survive `ConvertTo-Json` as text.** They serialise numerically, so state read back from PowerShell needs normalising before it can be compared against a target expressed in business terms. `alkivi_win_firewall` handles this by casting enums to strings in the PowerShell layer; be aware of it if you extend these modules. `bitlocker.get_status` returns values as PowerShell serialises them, and does not normalise them.
- **`win_updates.history` depends on an external page.** Release dates come from scraping `support.microsoft.com`; the field falls back to `"Release date not found"` when the page is unreachable or its markup changes. It also issues one HTTP request per installed hotfix, so it is slow on a well-patched host.
- **`azuread.matches` matches on a display-name substring**, which can pair the wrong accounts when names are similar. Review its output before acting on it.
- **`collect` is a common virtual name.** If another Salt tree already provides a `collect` module, the two will collide — expose this one only where you need it.

## Contributing

Match the surrounding style: modules are Windows-gated through `__virtual__`, PowerShell values are escaped with the module's `_ps_escape*` helpers rather than by string interpolation, and states must honour `__opts__['test']` and report accurate `changes`.

## License

Not yet specified. Contact Alkivi before redistributing.
