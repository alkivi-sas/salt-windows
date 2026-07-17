# -*- coding: utf-8 -*-
'''
Module for configuring Windows Firewall
'''
from __future__ import absolute_import

# Import python libs
import json
import re
import logging

# Import Salt libs
import salt.utils.platform
import salt.utils.win_lgpo_netsh
from salt.exceptions import CommandExecutionError

# Import salt libs
try:
    from salt.utils import platform
except ImportError:
    import salt.utils as platform

# Define the module's virtual name
__virtualname__ = 'alkivi_win_firewall'

log = logging.getLogger(__name__)


def __virtual__():
    '''
    Only works on Windows systems
    '''
    if platform.is_windows():
        return __virtualname__
    return False


def get_config():
    '''
    Return the Windows Firewall configuration for each profile (Domain, Private, Public)
    as a dict with profile name as key and settings in JSON-serializable format.

    Uses PowerShell Get-NetFirewallProfile. Each profile dict contains properties
    such as: Enabled, DefaultInboundAction, DefaultOutboundAction,
    AllowLocalFirewallRules, AllowLocalIPsecRules, NotifyOnListen,
    UnicastResponsesToMulticastBroadcast, LogFileName, LogAllowed, LogBlocked,
    LogIgnored, LogMaxSizeKilobytes, etc.

    Returns:
        dict: Mapping profile name -> settings dict (e.g. {"Domain": {...}, "Private": {...}, "Public": {...}}).

    CLI Example:

    .. code-block:: bash

        salt '*' alkivi_win_firewall.get_config
    '''
    script = (
        'Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, '
        'DefaultOutboundAction, AllowInboundRules, AllowLocalFirewallRules, AllowLocalIPsecRules, '
        'NotifyOnListen, UnicastResponsesToMulticastBroadcast, LogFileName, LogAllowed, '
        'LogBlocked, LogIgnored, LogMaxSizeKilobytes | ConvertTo-Json -Depth 3'
    )
    cmd = [
        'powershell',
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-Command', script,
    ]
    ret = __salt__['cmd.run_all'](cmd, python_shell=False)
    if ret['retcode'] != 0:
        raise CommandExecutionError(
            'Get-NetFirewallProfile failed: {0}'.format(
                ret.get('stderr') or ret.get('stdout', 'Unknown error'),
            )
        )
    out = (ret.get('stdout') or '').strip()
    if not out:
        return {}
    try:
        data = json.loads(out)
    except ValueError as e:
        log.error('Failed to parse PowerShell JSON output: %s', e)
        raise CommandExecutionError('Invalid JSON from PowerShell: {0}'.format(out[:200]))
    if isinstance(data, dict):
        data = [data]
    result = {}
    for item in data:
        name = item.get('Name')
        if name is None:
            continue
        result[name] = item
    return result


def add_ping_rule(name):
    '''
    .. versionadded:: 2015.5.0

    Add a new firewall rule for icmpv4

    CLI Example:

    .. code-block:: bash

        salt '*' firewall.add_rule 'alkivi_allow_icmp'
    '''
    protocol = 'icmpv4'
    dir = 'in'
    action = 'allow'
    cmd = ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
           'name={0}'.format(name),
           'protocol={0}'.format(protocol),
           'dir={0}'.format(dir),
           'action={0}'.format(action)]
    ret = __salt__['cmd.run'](cmd, python_shell=False)
    if isinstance(ret, str):
        return ret.strip() == 'Ok.'
    else:
        log.error('firewall.add_rule failed: {0}'.format(ret))
        return False


def add_rule(name, localport, protocol="tcp", action="allow", dir="in", remoteip="any"):
    """
    .. versionadded:: 2015.5.0

    Add a new inbound or outbound rule to the firewall policy

    Args:

        name (str): The name of the rule. Must be unique and cannot be "all".
            Required.

        localport (int): The port the rule applies to. Must be a number between
            0 and 65535. Can be a range. Can specify multiple ports separated by
            commas. Required.

        protocol (Optional[str]): The protocol. Can be any of the following:

            - A number between 0 and 255
            - icmpv4
            - icmpv6
            - tcp
            - udp
            - any

        action (Optional[str]): The action the rule performs. Can be any of the
            following:

            - allow
            - block
            - bypass

        dir (Optional[str]): The direction. Can be ``in`` or ``out``.

        remoteip (Optional [str]): The remote IP. Can be any of the following:

            - any
            - localsubnet
            - dns
            - dhcp
            - wins
            - defaultgateway
            - Any valid IPv4 address (192.168.0.12)
            - Any valid IPv6 address (2002:9b3b:1a31:4:208:74ff:fe39:6c43)
            - Any valid subnet (192.168.1.0/24)
            - Any valid range of IP addresses (192.168.0.1-192.168.0.12)
            - A list of valid IP addresses

            Can be combinations of the above separated by commas.

    Returns:
        bool: True if successful

    Raises:
        CommandExecutionError: If the command fails

    CLI Example:

    .. code-block:: bash

        salt '*' firewall.add_rule 'test' '8080' 'tcp'
        salt '*' firewall.add_rule 'test' '1' 'icmpv4'
        salt '*' firewall.add_rule 'test_remote_ip' '8000' 'tcp' 'allow' 'in' '192.168.0.1'
    """
    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        "name={0}".format(name),
        "protocol={0}".format(protocol),
        "dir={0}".format(dir),
        "action={0}".format(action),
        "remoteip={0}".format(remoteip),
    ]

    if protocol is None or ("icmpv4" not in protocol and "icmpv6" not in protocol and "any" not in protocol):
        cmd.append("localport={0}".format(localport))

    ret = __salt__["cmd.run_all"](cmd, python_shell=False, ignore_retcode=True)
    if ret["retcode"] != 0:
        raise CommandExecutionError(ret["stdout"])

    return True


# ForEach + ConvertTo-Json part of the PowerShell listing script
_PS_LIST_FOREACH = r'''ForEach-Object {
    $rule = $_
    $port = $rule | Get-NetFirewallPortFilter
    $address = $rule | Get-NetFirewallAddressFilter

    # Read enum values directly as strings to avoid fragile numeric mappings.
    $dirStr = [string]$rule.Direction
    $actionStr = [string]$rule.Action
    $profileStr = [string]$rule.Profile
    if ([string]::IsNullOrWhiteSpace($profileStr)) {
        $profileStr = 'Any'
    }

    $remoteRaw = $address.RemoteAddress
    if ($remoteRaw -eq 'Any') {
        $remoteNorm = 'Any'
    } elseif ($null -ne $remoteRaw -and $remoteRaw -is [System.Array]) {
        $remoteNorm = $remoteRaw
    } elseif ($null -ne $remoteRaw -and (Get-Member -InputObject $remoteRaw -Name 'Value' -MemberType Property -ErrorAction SilentlyContinue)) {
        $remoteNorm = $remoteRaw.Value
    } else {
        $remoteNorm = $remoteRaw
    }

    [PSCustomObject]@{
        Name          = $rule.Name
        DisplayName   = $rule.DisplayName
        Status        = if($rule.Enabled -eq 'True') { 'Active' } else { 'Inactive' }
        Direction     = $dirStr
        Action        = $actionStr
        Protocol      = $port.Protocol
        LocalAddress  = $address.LocalAddress
        LocalPort     = $port.LocalPort
        RemoteAddress = $remoteNorm
        RemotePort    = $port.RemotePort
        Profile       = $profileStr
        DisplayGroup  = $rule.DisplayGroup
        Group         = $rule.Group
        Description   = $rule.Description
    }
} | ConvertTo-Json -Depth 5'''


def _run_ps_list_rules(name=None, display_name=None, enabled=None, direction=None):
    '''Run the PowerShell listing script and return a list of dicts.'''
    filters = []
    if name is not None:
        filters.append("-Name '{0}'".format(str(name).replace("'", "''")))
    elif display_name is not None:
        filters.append("-DisplayName '{0}'".format(str(display_name).replace("'", "''")))

    if enabled is not None:
        if isinstance(enabled, bool):
            enabled_str = 'True' if enabled else 'False'
        else:
            val = str(enabled).strip().lower()
            if val in ('true', '1', 'yes', 'y'):
                enabled_str = 'True'
            elif val in ('false', '0', 'no', 'n'):
                enabled_str = 'False'
            else:
                raise CommandExecutionError('Invalid enabled value: {0}'.format(enabled))
        filters.append("-Enabled {0}".format(enabled_str))

    if direction is not None:
        d = str(direction).strip().lower()
        if d in ('in', 'inbound', 'incoming'):
            dir_str = 'Inbound'
        elif d in ('out', 'outbound', 'outgoing'):
            dir_str = 'Outbound'
        else:
            raise CommandExecutionError('Invalid direction value: {0}'.format(direction))
        filters.append("-Direction {0}".format(dir_str))

    get_cmd = "Get-NetFirewallRule"
    if filters:
        get_cmd = get_cmd + " " + " ".join(filters)
    get_cmd = get_cmd + " | "

    script = get_cmd + _PS_LIST_FOREACH
    cmd = [
        'powershell',
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-Command', script,
    ]
    ret = __salt__['cmd.run_all'](cmd, python_shell=False)
    if ret['retcode'] != 0:
        stderr = (ret.get('stderr') or '').strip()
        # When filtering by name/display_name and the rule does not exist,
        # Get-NetFirewallRule returns a non-zero code and an ObjectNotFound error.
        # In that case we want to treat it as "no rules" instead of a hard failure.
        not_found_markers = (
            'No MSFT_NetFirewallRule objects found',
            'CmdletizationQuery_NotFound',
        )
        if (name is not None or display_name is not None) and any(
            marker in stderr for marker in not_found_markers
        ):
            return []
        raise CommandExecutionError(stderr or ret.get('stdout', 'PowerShell command failed'))
    out = (ret.get('stdout') or '').strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except ValueError as e:
        log.error('Failed to parse PowerShell JSON output: %s', e)
        raise CommandExecutionError('Invalid JSON from PowerShell: {0}'.format(out[:200]))
    if isinstance(data, dict):
        return [data]
    return data


def ps_get_rules(enabled=True, direction='incoming'):
    '''
    List all Windows Firewall rules (via PowerShell NetSecurity),
    with optional filters by status (enabled/disabled) and direction.

    Each rule is returned with: DisplayName, Status, Direction, Action,
    Protocol, LocalAddress, LocalPort, RemoteAddress, RemotePort, Profile, DisplayGroup.

    Args:
        enabled (bool|str, optional): Filter by rule state.
            - True / 'true' / '1' / 'yes' => enabled rules only
            - False / 'false' / '0' / 'no' => disabled rules only
            - None (default) => no filter on state

        direction (str, optional): Rule direction.
            - 'incoming', 'inbound', 'in'  => Inbound
            - 'outgoing', 'outbound', 'out' => Outbound
            - None => no filter on direction

            Default: 'incoming'.

    Returns:
        list: List of dicts (one entry per rule).

    Raises:
        CommandExecutionError: If the PowerShell command fails.

    CLI Example:

    .. code-block:: bash

        salt '*' alkivi_win_firewall.ps_get_rules
        salt '*' alkivi_win_firewall.ps_get_rules enabled=True
        salt '*' alkivi_win_firewall.ps_get_rules direction=outgoing
        salt '*' alkivi_win_firewall.ps_get_rules enabled=False direction=incoming
    '''
    return _run_ps_list_rules(enabled=enabled, direction=direction)


def ps_get_rule(name=None, display_name=None):
    '''
    Get a firewall rule by name (GUID) or display name.

    Args:
        name (str, optional): Internal rule identifier (Name property, GUID type).
        display_name (str, optional): Display name (DisplayName).

    At least one of name or display_name must be provided.

    Returns:
        dict: The rule (same format as ps_get_rules), or None if not found.

    Raises:
        CommandExecutionError: If the command fails or no identifier is provided.

    CLI Example:

    .. code-block:: bash

        salt '*' alkivi_win_firewall.ps_get_rule display_name='My Rule'
        salt '*' alkivi_win_firewall.ps_get_rule name='{GUID-...}'
    '''
    if name is None and display_name is None:
        raise CommandExecutionError('Either name or display_name must be provided')
    rules = _run_ps_list_rules(name=name, display_name=display_name)
    if not rules:
        return None
    return rules[0]


def _ps_escape(value):
    '''Escape a value for use inside a PowerShell single-quoted string.'''
    return str(value).replace("'", "''")


def _ps_escape_like_literal(value):
    '''
    Escape special wildcard characters for PowerShell -like patterns.

    -like treats *, ?, [] as wildcards, so we escape them to match literally.
    '''
    s = str(value)
    s = s.replace('[', '[[]').replace(']', '[]]')
    s = s.replace('*', '[*]').replace('?', '[?]')
    return s


def ps_add_rule(
    display_name,
    direction='Inbound',
    action='Allow',
    protocol='TCP',
    local_port=None,
    remote_port=None,
    local_address=None,
    remote_address=None,
    profile=None,
    enabled=True,
    description=None,
    display_group=None,
    rule_name=None
):
    '''
    Add a rule to the Windows Firewall via New-NetFirewallRule (PowerShell).

    Args:
        display_name (str): Rule display name. Required.
        direction (str): Inbound or Outbound. Default Inbound.
        action (str): Allow or Block. Default Allow.
        protocol (str): TCP, UDP, Any, etc. Default TCP.
        local_port (str|int|list, optional): Local port(s), e.g. 443, \"80,443\", or [5060, \"40000-60000\"].
        remote_port (str|int|list, optional): Remote port(s). Same formats as local_port.
        local_address (str, optional): Local address(es) (e.g. Any, 192.168.0.0/24).
        remote_address (str, optional): Remote address(es).
        profile (str, optional): Domain, Private, Public (comma-separated).
        enabled (bool): Enable the rule. Default True.
        description (str, optional): Rule description.
        display_group (str, optional): Display group.
        rule_name (str, optional): Internal name (GUID); otherwise auto-generated by Windows.

    Returns:
        bool: True if the rule was created.

    Raises:
        CommandExecutionError: If the command fails.

    CLI Example:

    .. code-block:: bash

        salt '*' alkivi_win_firewall.ps_add_rule 'HTTP' direction=Inbound protocol=TCP local_port=80
    '''
    parts = [
        "New-NetFirewallRule",
        "-DisplayName", "'{0}'".format(_ps_escape(display_name)),
        "-Direction", direction,
        "-Action", action,
        "-Protocol", protocol,
        "-Enabled", str(enabled).replace("'", "''"),
    ]
    if rule_name is not None:
        parts.extend(["-Name", "'{0}'".format(_ps_escape(rule_name))])
    if local_port is not None:
        if isinstance(local_port, (list, tuple)):
            port_list = [str(x).strip() for x in local_port if str(x).strip()]
            if port_list:
                # -LocalPort accepts String[]: use PowerShell array syntax 'a','b'
                port_args = ",".join("'{0}'".format(_ps_escape(p)) for p in port_list)
                parts.extend(["-LocalPort", port_args])
        else:
            parts.extend(["-LocalPort", "'{0}'".format(_ps_escape(local_port))])
    if remote_port is not None:
        if isinstance(remote_port, (list, tuple)):
            port_list = [str(x).strip() for x in remote_port if str(x).strip()]
            if port_list:
                port_args = ",".join("'{0}'".format(_ps_escape(p)) for p in port_list)
                parts.extend(["-RemotePort", port_args])
        else:
            parts.extend(["-RemotePort", "'{0}'".format(_ps_escape(remote_port))])
    if local_address is not None:
        parts.extend(["-LocalAddress", "'{0}'".format(_ps_escape(local_address))])
    _ra = remote_address
    if _ra is not None:
        if isinstance(_ra, (list, tuple)):
            _ra = [str(x).strip() for x in _ra if str(x).strip()]
        elif isinstance(_ra, str) and not _ra.strip():
            _ra = None
        if _ra:
            if isinstance(_ra, list):
                remote_address_ps = ",".join(
                    "'{0}'".format(_ps_escape(x)) for x in _ra
                )
                parts.append("-RemoteAddress " + remote_address_ps)
            else:
                parts.extend(["-RemoteAddress", "'{0}'".format(_ps_escape(_ra))])
    if profile is not None:
        parts.extend(["-Profile", "'{0}'".format(_ps_escape(profile))])
    if description is not None:
        parts.extend(["-Description", "'{0}'".format(_ps_escape(description))])
    if display_group is not None:
        parts.extend(["-DisplayGroup", "'{0}'".format(_ps_escape(display_group))])
    script = " ".join(parts)
    cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "' + script.replace('"', '\\"') + '"'
    ret = __salt__['cmd.run_all'](cmd, python_shell=False, shell='powershell')
    if ret['retcode'] != 0:
        raise CommandExecutionError(ret.get('stderr') or ret.get('stdout', 'New-NetFirewallRule failed'))
    return True


def ps_del_rule(
    name=None,
    display_name=None,
    display_group=None,
    group=None,
    display_name_contains=None,
):
    '''
    Remove a rule from the Windows Firewall via Remove-NetFirewallRule (PowerShell).

    Args:
        name (str, optional): Internal rule identifier (Name / GUID).
        display_name (str, optional): Display name (DisplayName).
        display_group (str, optional): Firewall rule display group (DisplayGroup).
        group (str, optional): Firewall rule group (Group).
        display_name_contains (str, optional): Delete all rules where DisplayName contains
            this substring (wildcards are treated literally). Example:
            '(mDNS-In)' will match DisplayName like '* (mDNS-In) *'.

    At least one of name, display_name, display_group, group, or display_name_contains must be provided.

    Returns:
        list: List of deleted rules (each item includes Name, DisplayName, DisplayGroup, Group).
            Empty list means no matching rule.

    Raises:
        CommandExecutionError: If the command fails or no identifier is provided.

    CLI Example:

    .. code-block:: bash

        salt '*' alkivi_win_firewall.ps_del_rule display_name='Old rule'
        salt '*' alkivi_win_firewall.ps_del_rule name='{GUID-...}'
        salt '*' alkivi_win_firewall.ps_del_rule display_group='Windows Firewall Rules'
        salt '*' alkivi_win_firewall.ps_del_rule group='mDNS'
        salt '*' alkivi_win_firewall.ps_del_rule display_name_contains='(mDNS-In)'
    '''
    if (
        name is None
        and display_name is None
        and display_group is None
        and group is None
        and display_name_contains is None
    ):
        raise CommandExecutionError(
            'At least one of name, display_name, display_group, group, or display_name_contains must be provided'
        )

    filters = []
    if name is not None:
        filters.append("-Name '{0}'".format(_ps_escape(name)))
    if display_name is not None:
        filters.append("-DisplayName '{0}'".format(_ps_escape(display_name)))
    if display_group is not None:
        filters.append("-DisplayGroup '{0}'".format(_ps_escape(display_group)))
    if group is not None:
        filters.append("-Group '{0}'".format(_ps_escape(group)))

    get_cmd = 'Get-NetFirewallRule -ErrorAction SilentlyContinue'
    if filters:
        get_cmd = get_cmd + ' ' + ' '.join(filters)

    script_parts = []
    script_parts.append('$rules = ' + get_cmd)

    if display_name_contains is not None:
        # Escape -like wildcards, then wrap with '*' on both sides to implement "contains".
        escaped = _ps_escape_like_literal(display_name_contains)
        escaped = _ps_escape(escaped)
        pattern = '*{0}*'.format(escaped)
        script_parts.append(
            "$rules = $rules | Where-Object { $_.DisplayName -like '" + pattern + "' }"
        )

    # Always produce a JSON array ([]) even when no rules match.
    script_parts.append(
        '$deleted = @($rules | ForEach-Object { '
        '$r = $_; '
        'Remove-NetFirewallRule -InputObject $r -ErrorAction Stop | Out-Null; '
        '[PSCustomObject]@{'
        'Name=$r.Name; '
        'DisplayName=$r.DisplayName; '
        'DisplayGroup=$r.DisplayGroup; '
        'Group=$r.Group'
        '} '
        '})'
    )
    script_parts.append('$deleted | ConvertTo-Json -Depth 5')

    script = '; '.join(script_parts)
    cmd = [
        'powershell',
        '-NoProfile',
        '-ExecutionPolicy', 'Bypass',
        '-Command', script,
    ]

    ret = __salt__['cmd.run_all'](cmd, python_shell=False)
    if ret['retcode'] != 0:
        stderr = (ret.get('stderr') or '').strip()
        not_found_markers = (
            'No MSFT_NetFirewallRule objects found',
            'CmdletizationQuery_NotFound',
        )
        if any(marker in stderr for marker in not_found_markers):
            return []
        raise CommandExecutionError(stderr or ret.get('stdout', 'Remove-NetFirewallRule failed'))

    out = (ret.get('stdout') or '').strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except ValueError as e:
        raise CommandExecutionError('Invalid JSON from PowerShell: {0}'.format(out[:200]))
    if data is None:
        return []
    if isinstance(data, dict):
        return [data]
    return data


def ps_set_rule(
    name=None,
    display_name=None,
    new_display_name=None,
    direction=None,
    action=None,
    protocol=None,
    local_port=None,
    remote_port=None,
    local_address=None,
    remote_address=None,
    profile=None,
    enabled=None,
    description=None,
    display_group=None,
):
    '''
    Modify a Windows Firewall rule (Set-NetFirewallRule and port/address filters).

    Args:
        name (str, optional): Internal rule identifier (Name / GUID).
        display_name (str, optional): Display name (DisplayName).
        new_display_name (str, optional): New display name (-NewDisplayName).
        direction (str, optional): Inbound or Outbound.
        action (str, optional): Allow or Block.
        protocol (str, optional): TCP, UDP, Any (via Set-NetFirewallPortFilter).
        local_port (str|int|list, optional): Local port(s) (via Set-NetFirewallPortFilter). List or comma string.
        remote_port (str|int|list, optional): Remote port(s) (via Set-NetFirewallPortFilter). List or comma string.
        local_address (str, optional): Local address(es) (via Set-NetFirewallAddressFilter).
        remote_address (str, optional): Remote address(es) (via Set-NetFirewallAddressFilter).
        profile (str, optional): Domain, Private, Public.
        enabled (bool, optional): Enable or disable the rule.
        description (str, optional): Description.
        display_group (str, optional): Display group.

    At least one of name or display_name must be provided. At least one modification parameter.

    Returns:
        bool: True if the rule was modified.

    Raises:
        CommandExecutionError: If the command fails.

    CLI Example:

    .. code-block:: bash

        salt '*' alkivi_win_firewall.ps_set_rule display_name='HTTP' enabled=False
        salt '*' alkivi_win_firewall.ps_set_rule name='{GUID}' local_port=443
    '''
    if name is None and display_name is None:
        raise CommandExecutionError('Either name or display_name must be provided')
    rule_params = dict(
        new_display_name=new_display_name,
        direction=direction,
        action=action,
        profile=profile,
        enabled=enabled,
        description=description,
        display_group=display_group,
    )
    port_params = (protocol, local_port, remote_port)
    address_params = (local_address, remote_address)
    if not any(v is not None for v in list(rule_params.values()) + list(port_params) + list(address_params)):
        raise CommandExecutionError('At least one modification parameter must be provided')
    if name is not None:
        id_arg = "-Name '{0}'".format(_ps_escape(name))
        get_id = "Get-NetFirewallRule -Name '{0}'".format(_ps_escape(name))
    else:
        id_arg = "-DisplayName '{0}'".format(_ps_escape(display_name))
        get_id = "Get-NetFirewallRule -DisplayName '{0}'".format(_ps_escape(display_name))

    scripts = []

    if any(v is not None for v in rule_params.values()):
        parts = ["Set-NetFirewallRule", id_arg]
        if new_display_name is not None:
            parts.extend(["-NewDisplayName", "'{0}'".format(_ps_escape(new_display_name))])
        if direction is not None:
            parts.append("-Direction {0}".format(direction))
        if action is not None:
            parts.append("-Action {0}".format(action))
        if profile is not None:
            parts.extend(["-Profile", "'{0}'".format(_ps_escape(profile))])
        if enabled is not None:
            parts.extend(["-Enabled", str(enabled)])
        if description is not None:
            parts.extend(["-Description", "'{0}'".format(_ps_escape(description))])
        if display_group is not None:
            parts.extend(["-DisplayGroup", "'{0}'".format(_ps_escape(display_group))])
        scripts.append(" ".join(parts))

    if any(v is not None for v in port_params):
        parts = [get_id + " | Get-NetFirewallPortFilter | Set-NetFirewallPortFilter"]
        if protocol is not None:
            parts.append("-Protocol '{0}'".format(_ps_escape(protocol)))
        if local_port is not None:
            if isinstance(local_port, (list, tuple)):
                port_list = [str(x).strip() for x in local_port if str(x).strip()]
                if port_list:
                    port_args = ",".join("'{0}'".format(_ps_escape(p)) for p in port_list)
                    parts.append("-LocalPort " + port_args)
            else:
                parts.append("-LocalPort '{0}'".format(_ps_escape(str(local_port))))
        if remote_port is not None:
            if isinstance(remote_port, (list, tuple)):
                port_list = [str(x).strip() for x in remote_port if str(x).strip()]
                if port_list:
                    port_args = ",".join("'{0}'".format(_ps_escape(p)) for p in port_list)
                    parts.append("-RemotePort " + port_args)
            else:
                parts.append("-RemotePort '{0}'".format(_ps_escape(str(remote_port))))
        scripts.append(" ".join(parts))

    if any(v is not None for v in address_params):
        if isinstance(remote_address, (list, tuple)):
            # Set-NetFirewallAddressFilter -RemoteAddress expects String[], not a comma-separated string
            remote_address_ps = ",".join(
                "'{0}'".format(_ps_escape(str(x).strip())) for x in remote_address
            )
            remote_arg = "-RemoteAddress " + remote_address_ps
        else:
            remote_address_ps = remote_address
            remote_arg = "-RemoteAddress '{0}'".format(_ps_escape(remote_address_ps)) if remote_address_ps else None

        parts = [get_id + " | Get-NetFirewallAddressFilter | Set-NetFirewallAddressFilter"]
        if local_address is not None:
            parts.append("-LocalAddress '{0}'".format(_ps_escape(local_address)))
        if remote_arg is not None:
            parts.append(remote_arg)
        scripts.append(" ".join(parts))

    for script in scripts:
        cmd = 'powershell -NoProfile -ExecutionPolicy Bypass -Command "' + script.replace('"', '\\"') + '"'
        ret = __salt__['cmd.run_all'](cmd, python_shell=False, shell='powershell')
        if ret['retcode'] != 0:
            raise CommandExecutionError(ret.get('stderr') or ret.get('stdout', 'Set rule failed'))
    return True
